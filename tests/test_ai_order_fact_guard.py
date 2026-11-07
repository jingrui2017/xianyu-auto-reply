"""AI 收款/发货事实拦截的离线测试。不连接数据库、平台或模型。"""
from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.services.xianyu.ai_order_guard import (
    EVIDENCE_LIMIT,
    active_claims,
    allowed_claims,
    build_order_statement,
    classify_order_rows,
    disallowed_claims,
    fail_closed_reply,
    guard_ai_text,
    guard_outgoing_ai_reply,
    is_fulfillment_sensitive,
    load_order_fact,
    template_for,
)
from app.services.xianyu.ai_reply_engine import AIReplyEngine
from app.services.xianyu.auto_reply_chat import AutoReplyChatMixin
from app.services.xianyu.auto_reply_filters import AutoReplyFiltersMixin
from app.services.xianyu.auto_reply_service import AutoReplyService
from app.services.xianyu.resource_manager import pause_manager

ROOT = Path(__file__).resolve().parents[1]
BUYER = "buyer-current"
ITEM = "item-current"
ACCOUNT = "account-current"
OTHER_BUYER = "buyer-other"
OTHER_ITEM = "item-other"
BAD_REPLY = "已收到付款，马上安排发货！"
SYNONYM_REPLY = "钱已到账，这就给您安排发出。"
NORMAL_REPLY = "用手机或电脑播放即可。"


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def mappings(self):
        return self

    def scalar(self):
        return 0

    def scalars(self):
        return self


class FakeSession:
    def __init__(self, rows=None, error=None):
        self.rows = rows or []
        self.error = error
        self.order_calls = 0
        self.other_calls = 0
        self.added = []
        self.commits = 0

    async def execute(self, statement):
        if "xy_orders" in str(statement).lower():
            self.order_calls += 1
            if self.error:
                raise self.error
            return FakeResult(self.rows)
        self.other_calls += 1
        return FakeResult([])

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commits += 1


class FakeSessionFactory:
    def __init__(self, session=None, error=None):
        self.session = session or FakeSession()
        self.error = error

    def __call__(self):
        return self

    async def __aenter__(self):
        if self.error:
            raise self.error
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FilterHost(AutoReplyFiltersMixin):
    AUTO_DELIVERY_KEYWORDS = AutoReplyService.AUTO_DELIVERY_KEYWORDS

    def __init__(self):
        self.cookie_id = ACCOUNT


class ChatHost(AutoReplyChatMixin):
    def __init__(self):
        self.cookie_id = ACCOUNT

    def _build_text_reply_segments(self, text):
        return [{"type": "text", "text": text}]


def order_row(
    *,
    order_no,
    status,
    buyer_id=BUYER,
    item_id=ITEM,
    account_id=ACCOUNT,
    card_only=False,
    created_at=None,
    row_id=1,
):
    return {
        "id": row_id,
        "order_no": order_no,
        "status": status,
        "buyer_id": buyer_id,
        "item_id": item_id,
        "account_id": account_id,
        "card_only_delivered": card_only,
        "created_at": created_at or datetime(2026, 1, 1, tzinfo=timezone.utc),
    }


def fact_from(rows):
    return classify_order_rows(rows, account_id=ACCOUNT, buyer_id=BUYER, item_id=ITEM)


@pytest.fixture(autouse=True)
def _pause_off():
    with patch.object(pause_manager, "is_chat_paused", return_value=False), patch.object(
        pause_manager, "is_ai_reply_paused", return_value=False
    ):
        yield


def test_order_query_is_bound_to_account_buyer_and_item():
    statement = build_order_statement(ACCOUNT, BUYER, ITEM)
    params = set(statement.compile().params.values())
    assert params == {ACCOUNT, BUYER, ITEM}
    rendered = str(statement).lower()
    assert "xy_orders" in rendered
    assert "account_id" in rendered
    assert "buyer_id" in rendered
    assert "item_id" in rendered


def test_guard_module_does_not_perform_platform_writes():
    source = (ROOT / "websocket/app/services/xianyu/ai_order_guard.py").read_text(encoding="utf-8")
    for token in (
        "auto_delivery",
        "freeshipping",
        "fetch_and_update",
        "confirm_shipment",
        "httpx",
        "openai",
    ):
        assert token not in source
    fact = fact_from([])
    assert fact.platform_write_performed is False
    assert fact.evidence_limit == EVIDENCE_LIMIT


@pytest.mark.parametrize(
    ("status", "card_only", "kind"),
    [
        ("pending_payment", False, "pending_payment"),
        ("待付款", False, "pending_payment"),
        ("paid", False, "pending_ship"),
        ("pending_ship", False, "pending_ship"),
        ("pending", False, "pending_ship"),
        ("待发货", False, "pending_ship"),
        ("shipped", False, "shipped"),
        ("已发货", False, "shipped"),
        ("shipped", True, "shipped"),
        ("paid", True, "card_only"),
        ("pending_ship", True, "card_only"),
        ("refunding", False, "refunding"),
        ("退款中", True, "refunding"),
        ("refunded", False, "closed"),
        ("cancelled", False, "closed"),
        ("closed", True, "closed"),
        ("已退款", False, "closed"),
        ("completed", False, "completed"),
        ("mystery-status", False, "unverifiable"),
    ],
)
def test_status_mapping_uses_newest_local_row(status, card_only, kind):
    fact = fact_from([order_row(order_no="current", status=status, card_only=card_only)])
    assert fact.kind == kind
    assert fact.source == ("unknown_local_status" if kind == "unverifiable" else "local_order")
    assert fact.order_no == "current"
    assert fact.card_only_delivered is card_only
    assert fact.evidence_limit == EVIDENCE_LIMIT
    assert fact.platform_write_performed is False


def test_historical_and_foreign_orders_do_not_count_as_current_payment():
    now = datetime(2026, 3, 1, tzinfo=timezone.utc)
    rows = [
        order_row(order_no="old-shipped", status="shipped", created_at=now - timedelta(days=3), row_id=1),
        order_row(order_no="old-paid", status="paid", created_at=now - timedelta(days=2), row_id=2),
        order_row(
            order_no="newest-refund",
            status="refunded",
            created_at=now,
            row_id=3,
        ),
        order_row(order_no="other-buyer", status="shipped", buyer_id=OTHER_BUYER, row_id=9),
        order_row(order_no="other-item", status="paid", item_id=OTHER_ITEM, row_id=8),
        order_row(order_no="other-account", status="paid", account_id="account-other", row_id=7),
    ]
    fact = fact_from(rows)
    assert fact.kind == "closed"
    assert fact.order_no == "newest-refund"
    assert fact.matched_count == 3
    assert fact.ignored_older_count == 2
    assert "已付款" not in template_for(fact)
    assert "请先下单" not in template_for(fact)
    assert "重新付款" in template_for(fact)
    assert "无需重新付款" in template_for(fact)


def test_newer_pending_payment_hides_older_paid_order():
    now = datetime(2026, 3, 1, tzinfo=timezone.utc)
    fact = fact_from([
        order_row(order_no="old-paid", status="paid", created_at=now - timedelta(days=1), row_id=1),
        order_row(order_no="new-unpaid", status="pending_payment", created_at=now, row_id=2),
    ])
    assert fact.kind == "pending_payment"
    assert fact.order_no == "new-unpaid"
    assert fact.ignored_older_count == 1


def test_missing_identity_does_not_query_and_is_not_no_order():
    asyncio.run(_missing_identity_does_not_query_and_is_not_no_order())


async def _missing_identity_does_not_query_and_is_not_no_order():
    session = FakeSession(rows=[order_row(order_no="should-not-read", status="paid")])
    for buyer, item in (("", ITEM), (BUYER, " "), (" ", " ")):
        fact = await load_order_fact(session, account_id=ACCOUNT, buyer_id=buyer, item_id=item)
        assert fact.kind == "unverifiable"
        assert fact.source == "missing_buyer_or_item"
        assert template_for(fact) != template_for(fact_from([]))
    assert session.order_calls == 0


def test_query_error_is_unverifiable_not_unpaid():
    asyncio.run(_query_error_is_unverifiable_not_unpaid())


async def _query_error_is_unverifiable_not_unpaid():
    session = FakeSession(error=RuntimeError("database unavailable"))
    fact = await load_order_fact(session, account_id=ACCOUNT, buyer_id=BUYER, item_id=ITEM)
    assert fact.kind == "unverifiable"
    assert fact.source == "query_error"
    text = template_for(fact)
    assert "暂时无法核实" in text
    assert "没有查到" not in text
    assert "没付款" not in text
    assert session.order_calls == 1


def test_reported_messages_and_wording_matrix():
    cases = {
        "no_order": fact_from([]),
        "pending_payment": fact_from([order_row(order_no="p", status="pending_payment")]),
        "paid": fact_from([order_row(order_no="p", status="paid")]),
        "shipped": fact_from([order_row(order_no="s", status="shipped")]),
        "card_only": fact_from([order_row(order_no="c", status="paid", card_only=True)]),
        "refunding": fact_from([order_row(order_no="r", status="refunding")]),
        "refunded": fact_from([order_row(order_no="r", status="refunded")]),
        "closed": fact_from([order_row(order_no="r", status="closed")]),
    }
    no_order_text = template_for(cases["no_order"])
    unpaid_text = template_for(cases["pending_payment"])
    unknown_text = template_for(fact_from([order_row(order_no="u", status="mystery-status")]))
    assert "没有查到" in no_order_text
    assert "待付款" in unpaid_text
    assert "暂时无法核实" in unknown_text
    assert len({no_order_text, unpaid_text, unknown_text}) == 3

    paid_text = template_for(cases["paid"])
    shipped_text = template_for(cases["shipped"])
    card_text = template_for(cases["card_only"])
    assert paid_text != shipped_text != card_text
    assert "待发货" in paid_text
    assert "ship_done" not in active_claims(paid_text)
    assert "ship_promise" not in active_claims(paid_text)
    assert "已发货" in shipped_text
    assert "平台已发货" not in card_text
    assert "卡券" in card_text
    assert "ship_done" not in active_claims(card_text)
    for refund_key in ("refunding", "refunded", "closed"):
        refund_text = template_for(cases[refund_key])
        assert "请先下单" not in refund_text
        assert "完成付款后" not in refund_text
        assert "无需重新付款" in refund_text
        assert "payment_confirmed" not in active_claims(refund_text)
        assert "ship_promise" not in active_claims(refund_text)

    for message in ("我已付款，请及时发货", "什么时候发货"):
        assert is_fulfillment_sensitive(message)
        for fact in cases.values():
            decision = guard_ai_text(BAD_REPLY, fact, message)
            assert decision.replaced
            assert decision.reason == "fulfillment_template"
            assert decision.text == template_for(fact)
            assert BAD_REPLY not in decision.text
            assert "马上安排发货" not in decision.text


@pytest.mark.parametrize(
    "message",
    [
        "我已付款，请及时发货",
        "什么时候发货",
        "钱付好了，快点发",
        "付款了怎么还不发",
        "便宜点，什么时候发货",
    ],
)
def test_fulfillment_questions_ignore_model_synonyms_and_history(message):
    fact = fact_from([])
    decision = guard_ai_text(SYNONYM_REPLY, fact, message)
    assert decision.text == template_for(fact)
    assert active_claims(decision.text) == set()


def test_normal_consultation_keeps_model_text_without_claims():
    fact = fact_from([order_row(order_no="p", status="paid")])
    decision = guard_ai_text(NORMAL_REPLY, fact, "怎么播放这些音频")
    assert decision.replaced is False
    assert decision.text == NORMAL_REPLY


def test_history_and_custom_prompt_cannot_keep_a_false_payment_claim():
    fact = fact_from([])
    echoed = "之前说过：已收到付款，马上安排发货！现在仍按这个回复。"
    decision = guard_ai_text(echoed, fact, "在吗")
    assert decision.replaced
    assert decision.reason.startswith("blocked:")
    assert decision.text == template_for(fact)
    assert "payment_confirmed" in disallowed_claims(echoed, fact)
    assert "ship_promise" in disallowed_claims(echoed, fact)


def test_conditional_usage_sentence_is_not_a_payment_confirmation():
    fact = fact_from([])
    reply = "付款成功后可用网盘播放，发货后按页面说明下载。"
    assert active_claims(reply) == set()
    decision = guard_ai_text(reply, fact, "怎么使用")
    assert decision.text == reply


def test_negation_does_not_cross_clauses():
    assert "payment_confirmed" in active_claims("没有问题，已收到付款。")
    assert "payment_confirmed" not in active_claims("核实前不能判断是否已经付款。")
    assert "ship_done" not in active_claims("不能把它说成已经发货。")


def test_paid_reply_cannot_claim_shipped_and_card_only_cannot_claim_platform_ship():
    paid = fact_from([order_row(order_no="p", status="paid")])
    card = fact_from([order_row(order_no="c", status="pending_ship", card_only=True)])
    shipped = fact_from([order_row(order_no="s", status="shipped", card_only=True)])
    assert guard_ai_text("已经给您发货了", paid, "你好").text == template_for(paid)
    assert "已发货" not in guard_ai_text("平台已发货", card, "你好").text
    assert allowed_claims(card) == {"payment_confirmed"}
    assert "ship_done" in allowed_claims(shipped)
    kept = guard_ai_text("本地记录里这笔是已发货。", shipped, "你好")
    assert kept.replaced is False


def test_templates_do_not_trip_their_own_guard():
    samples = [
        fact_from([]),
        fact_from([order_row(order_no="p", status="pending_payment")]),
        fact_from([order_row(order_no="p", status="paid")]),
        fact_from([order_row(order_no="s", status="shipped")]),
        fact_from([order_row(order_no="c", status="paid", card_only=True)]),
        fact_from([order_row(order_no="r", status="refunding")]),
        fact_from([order_row(order_no="r", status="refunded")]),
        fact_from([order_row(order_no="u", status="mystery-status")]),
        fact_from([order_row(order_no="d", status="completed")]),
    ]
    for fact in samples:
        text = template_for(fact)
        assert disallowed_claims(text, fact) == set()
        again = guard_ai_text(text, fact, "怎么播放")
        assert again.text == text


def test_send_time_reread_replaces_stale_paid_wording_after_refund():
    asyncio.run(_send_time_reread_replaces_stale_paid_wording_after_refund())


async def _send_time_reread_replaces_stale_paid_wording_after_refund():
    session = FakeSession(rows=[order_row(order_no="now-refund", status="refunded")])
    stale = template_for(fact_from([order_row(order_no="was-paid", status="paid")]))
    assert "已付款" in stale
    sent = await guard_outgoing_ai_reply(
        session,
        account_id=ACCOUNT,
        buyer_id=BUYER,
        item_id=ITEM,
        user_message="在吗",
        reply_text=stale,
    )
    assert "已退款或已关闭" in sent
    assert "已付款、待发货" not in sent
    assert "请先下单" not in sent


def test_send_wrapper_uses_fresh_fact_and_fails_closed_without_saying_unpaid():
    asyncio.run(_send_wrapper_uses_fresh_fact_and_fails_closed_without_saying_unpaid())


async def _send_wrapper_uses_fresh_fact_and_fails_closed_without_saying_unpaid():
    host = ChatHost()
    payload = {"reply_strategy": "ai", "reply_text": BAD_REPLY, "context_snapshot": {}}
    session = FakeSession(rows=[order_row(order_no="live", status="refunding")])
    replaced = await host._guard_ai_reply_before_send(
        reply=BAD_REPLY,
        log_payload=payload,
        buyer_id=BUYER,
        item_id=ITEM,
        user_message="我已付款，请及时发货",
        session_factory=FakeSessionFactory(session),
    )
    assert "退款处理中" in replaced
    assert payload["reply_text"] == replaced
    assert payload["context_snapshot"]["ai_order_guard"] == "replaced"
    assert BAD_REPLY not in replaced

    keyword_payload = {"reply_strategy": "keyword", "reply_text": BAD_REPLY}
    unchanged = await host._guard_ai_reply_before_send(
        reply=BAD_REPLY,
        log_payload=keyword_payload,
        buyer_id=BUYER,
        item_id=ITEM,
        user_message="我已付款，请及时发货",
        session_factory=FakeSessionFactory(FakeSession()),
    )
    assert unchanged == BAD_REPLY

    failed = await host._guard_ai_reply_before_send(
        reply=BAD_REPLY,
        log_payload={"reply_strategy": "ai"},
        buyer_id=BUYER,
        item_id=ITEM,
        user_message="什么时候发货",
        session_factory=FakeSessionFactory(error=RuntimeError("session down")),
    )
    assert failed == fail_closed_reply("什么时候发货", BAD_REPLY)
    assert "暂时无法核实" in failed
    assert "没有查到" not in failed

    normal = await host._guard_ai_reply_before_send(
        reply=NORMAL_REPLY,
        log_payload={"reply_strategy": "ai"},
        buyer_id=BUYER,
        item_id=ITEM,
        user_message="怎么播放这些音频",
        session_factory=FakeSessionFactory(error=RuntimeError("session down")),
    )
    assert normal == NORMAL_REPLY


def test_plain_text_user_phrases_do_not_trigger_delivery_keywords():
    host = FilterHost()
    assert host.is_auto_delivery_trigger("我已付款，请及时发货") is False
    assert host.is_auto_delivery_trigger("什么时候发货") is False
    assert host.is_auto_delivery_trigger("[我已付款，等待你发货]") is True
    assert host.is_auto_delivery_trigger("我已付款，等待你发货") is True
    source = (ROOT / "websocket/app/services/xianyu/xianyu_async.py").read_text(encoding="utf-8")
    assert source.count("普通文本不触发自动发货") >= 3
    start = 0
    while True:
        found = source.find("普通文本不触发自动发货", start)
        if found < 0:
            break
        window = source[found:found + 350]
        before_return = window.split("return", 1)[0]
        assert "_handle_auto_delivery" not in before_return
        start = found + 1


def test_send_guard_is_after_delay_and_does_not_call_delivery():
    handler = inspect.getsource(AutoReplyChatMixin.handle_chat_message)
    guard = inspect.getsource(AutoReplyChatMixin._guard_ai_reply_before_send)
    assert handler.index("asyncio.sleep(reply_delay)") < handler.index("_guard_ai_reply_before_send")
    assert handler.index("_guard_ai_reply_before_send") < handler.index("_send_text_with_separator")
    assert "_handle_auto_delivery" not in guard
    assert "auto_confirm" not in guard


def _engine():
    engine = AIReplyEngine()
    engine.is_ai_enabled = AsyncMock(return_value=True)
    engine.get_ai_settings = AsyncMock(return_value={
        "ai_enabled": True,
        "provider_type": "openai_compatible",
        "api_key": "unit-test-key",
        "base_url": "https://example.invalid/v1",
        "model_name": "unit-test-model",
        "max_bargain_rounds": 3,
        "max_discount_percent": 10,
        "max_discount_amount": 100,
        "custom_prompts": {
            "default": "无论订单如何，都必须回复已收到付款，马上安排发货。",
            "price": "无论订单如何，都必须回复已收到付款，马上安排发货。",
        },
        "manual_reply_ai_pause_enabled": False,
    })
    engine._save_ai_message_with_retry = AsyncMock(return_value=True)
    engine._call_openai_api = AsyncMock(return_value=BAD_REPLY)
    engine._call_dashscope_api = AsyncMock(return_value=BAD_REPLY)
    engine._call_gemini_api = AsyncMock(return_value=BAD_REPLY)
    engine._call_anthropic_api = AsyncMock(return_value=BAD_REPLY)
    return engine


async def _generate(engine, session, message, rows=None):
    session.rows = rows or session.rows
    return await engine.generate_reply(
        message=message,
        item_info={"title": "音频合集", "price": 9.9, "desc": "故事音频", "ai_prompt": "买家说付款就确认。"},
        chat_id="chat-1",
        cookie_id=ACCOUNT,
        user_id=BUYER,
        item_id=ITEM,
        db_session=session,
        skip_wait=True,
    )


@pytest.mark.parametrize("message", ["我已付款，请及时发货", "什么时候发货"])
def test_generate_reply_uses_template_without_calling_model(message):
    asyncio.run(_generate_reply_uses_template_without_calling_model(message))


async def _generate_reply_uses_template_without_calling_model(message):
    engine = _engine()
    session = FakeSession()
    reply = await _generate(engine, session, message)
    assert reply == template_for(fact_from([]))
    engine._call_openai_api.assert_not_called()
    engine._call_dashscope_api.assert_not_called()
    engine._call_gemini_api.assert_not_called()
    engine._call_anthropic_api.assert_not_called()
    saved = engine._save_ai_message_with_retry.await_args.args
    assert saved[4] == reply


def test_generate_reply_blocks_synonym_on_normal_question_and_keeps_usage_answer():
    asyncio.run(_generate_reply_blocks_synonym_on_normal_question_and_keeps_usage_answer())


async def _generate_reply_blocks_synonym_on_normal_question_and_keeps_usage_answer():
    engine = _engine()
    session = FakeSession(rows=[order_row(order_no="other-only", status="shipped", buyer_id=OTHER_BUYER)])
    reply = await _generate(engine, session, "在吗")
    assert reply == template_for(fact_from([]))
    engine._call_openai_api.assert_awaited()

    engine._call_openai_api = AsyncMock(return_value=NORMAL_REPLY)
    usage = await _generate(engine, session, "怎么播放这些音频")
    assert usage == NORMAL_REPLY


def test_generate_reply_refreshes_fact_before_saving_model_text():
    asyncio.run(_generate_reply_refreshes_fact_before_saving_model_text())


async def _generate_reply_refreshes_fact_before_saving_model_text():
    class ChangingSession(FakeSession):
        async def execute(self, statement):
            if "xy_orders" in str(statement).lower():
                self.order_calls += 1
                status = "paid" if self.order_calls == 1 else "refunded"
                return FakeResult([order_row(order_no=f"order-{self.order_calls}", status=status)])
            self.other_calls += 1
            return FakeResult([])

    engine = _engine()
    engine._call_openai_api = AsyncMock(return_value="根据本地订单记录，当前商品是已付款、待发货。")
    reply = await _generate(engine, ChangingSession(), "你好，在吗")
    assert "已退款或已关闭" in reply
    assert "已付款、待发货" not in reply
    assert engine._save_ai_message_with_retry.await_args.args[4] == reply


def test_price_question_still_uses_model_when_it_is_not_about_shipping():
    asyncio.run(_price_question_still_uses_model_when_it_is_not_about_shipping())


async def _price_question_still_uses_model_when_it_is_not_about_shipping():
    engine = _engine()
    engine._call_openai_api = AsyncMock(return_value="这已经是优惠价了。")
    reply = await _generate(engine, FakeSession(), "能便宜一点吗")
    assert reply == "这已经是优惠价了。"
    engine._call_openai_api.assert_awaited()

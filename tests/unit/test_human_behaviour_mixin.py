"""HumanBehaviourMixin tests -- verify human-like interaction helpers."""
from unittest.mock import MagicMock, patch


def test_type_with_delays_sends_keys_one_by_one():
    from agents.human_behaviour import HumanBehaviourMixin
    mixin = HumanBehaviourMixin()
    mock_element = MagicMock()
    with patch("time.sleep"):
        mixin.type_with_delays(mock_element, "hello")
    assert mock_element.send_keys.call_count == 5


def test_smooth_scroll_executes_js():
    from agents.human_behaviour import HumanBehaviourMixin
    mixin = HumanBehaviourMixin()
    driver = MagicMock()
    with patch("time.sleep"):
        mixin.smooth_scroll(driver, distance=500)
    assert driver.execute_script.called


def test_random_pause_sleeps_within_range():
    from agents.human_behaviour import HumanBehaviourMixin
    mixin = HumanBehaviourMixin()
    with patch("time.sleep") as mock_sleep:
        mixin.random_pause(min_s=0.5, max_s=1.5)
        call_args = mock_sleep.call_args[0][0]
        assert 0.5 <= call_args <= 1.5


def test_bezier_mouse_move_calls_action_chain():
    from agents.human_behaviour import HumanBehaviourMixin
    from unittest.mock import patch, MagicMock
    mixin = HumanBehaviourMixin()
    mock_driver = MagicMock()
    with patch("agents.human_behaviour.ActionChains") as mock_ac_cls:
        mock_ac = MagicMock()
        mock_ac_cls.return_value = mock_ac
        mock_ac.move_by_offset.return_value = mock_ac
        mock_ac.perform.return_value = None
        with patch("time.sleep"):
            mixin.bezier_mouse_move(mock_driver, dx=100, dy=50)
        assert mock_ac.move_by_offset.call_count >= 3

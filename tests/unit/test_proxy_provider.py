"""ProxyProvider stub tests."""


def test_proxy_provider_interface_importable():
    from agents.proxy_provider import ProxyProvider
    p = ProxyProvider()
    assert p.get_proxy() is None


def test_proxy_provider_noop_rotate():
    from agents.proxy_provider import ProxyProvider
    p = ProxyProvider()
    p.rotate()  # must not raise

from lanecheck.robots import allowed, parse_robots


def test_exact_token_beats_star_and_longest_allow_wins():
    groups = parse_robots(
        """
        User-agent: *
        Disallow: /

        User-agent: Storebot-Google
        Disallow: /
        Allow: /products
        Allow: /cart
        """
    )
    assert allowed(groups, "Storebot-Google", "/products/hat")
    assert allowed(groups, "Storebot-Google", "/cart")
    assert not allowed(groups, "Storebot-Google", "/checkout")
    assert not allowed(groups, "OAI-SearchBot", "/")


def test_equal_length_allow_wins_and_dollar_anchors():
    groups = parse_robots(
        """
        User-agent: Claude-User
        Allow: /cart
        Disallow: /cart
        Disallow: /checkout$
        """
    )
    assert allowed(groups, "claude-user", "/cart")
    assert not allowed(groups, "Claude-User", "/checkout")
    assert allowed(groups, "Claude-User", "/checkout/next")


def test_empty_disallow_matches_nothing():
    groups = parse_robots(
        """
        User-agent: PerplexityBot
        Disallow:
        """
    )
    assert allowed(groups, "PerplexityBot", "/products/hat")

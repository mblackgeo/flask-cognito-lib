from flask_cognito_lib.utils import generate_code_challenge, generate_code_verifier


def test_generate_code_challenge() -> None:
    secret = generate_code_verifier(40)
    verify = generate_code_challenge(secret)

    assert len(secret) >= 45
    assert len(verify) == 43

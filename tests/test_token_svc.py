from jwt import PyJWKSet

from flask_cognito_lib.services.token_svc import TokenService


def test_verify_access_token(mocker, jwks, cfg):
    mocker.patch(
        "jwt.jwks_client.PyJWKClient.get_jwk_set",
        return_value=PyJWKSet.from_dict(jwks),
    )
    serv = TokenService(cfg=cfg)

    token = (
        "eyJraWQiOiIyZ0g0MkZIQkxkZlN2MVlRd21xbDZiaTQ1c1gzZG92c3Z2dUNYUVE2VWF3PSIsImFsZyI6IlJTMjU2In0."
        "eyJzdWIiOiI5MDQ4ZDM4Zi04MTc0LTQ5YjktOGQ1OS0zMjM4MTcyODIzZDgiLCJjb2duaXRvOmdyb3VwcyI6WyJhZG1pbiJdLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb21cL2V1LXdlc3QtMV9jN085MFNOREYiLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiI0bGxuNjY3MjZwcDNmNGdpMWtyajBzdGE5aCIsIm9yaWdpbl9qdGkiOiJkNDgxMWJmMS0yNzk4LTRkMzMtYjY1Yy0yZjgyNTQ3MjlkZDIiLCJldmVudF9pZCI6IjE4ODI4ZDE4LWI0NjUtNDcwZS04NGI2LTE3NTIwZGVkMjk5YiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoicGhvbmUgb3BlbmlkIGVtYWlsIiwiYXV0aF90aW1lIjoxNjQ3OTYxNDkzLCJleHAiOjE2NDc5NjUwOTMsImlhdCI6MTY0Nzk2MTQ5MywianRpIjoiMGZlMjlhOWUtNmU5NC00NzliLTk4N2ItZTQ1Njk2ZDU4NDNhIiwidXNlcm5hbWUiOiJtYmxhY2sifQ."
        "U0ucoBT7X40jGuuJpDpxLhlL3084Qc_Sq5MAfIoHvujRMqdea6_2QEMrT-p4XvYVQArYmJKPuP40N8i5YR_fOyoW_truqzFtu-MiCCBGOCVXZ0yZ5K8YX6Arb0TbZiyFsU1fj-qx_DmlQIuPDoiTNVo4_d0Ff1NvsHtYZ-00A-7cAtZIu9FvuEumIqOTawBXv4O5QViRYmnnS6hGl8Fh0-N8Eutb_MnhJk47xulvNcoCUIzw7GX8ayn6WgLDdEHYvJs1zrXiyBDx4T5oV667PdELc-DQOy4j6vBlXxjc-fptVT9k-AD_p_Pe70xvzBhFejKCQz5fI0FF7_MM683fIw"
    )

    claims = serv.verify_access_token(token, leeway=1e9)
    assert claims == {
        "sub": "9048d38f-8174-49b9-8d59-3238172823d8",
        "cognito:groups": ["admin"],
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_c7O90SNDF",
        "version": 2,
        "client_id": "4lln66726pp3f4gi1krj0sta9h",
        "origin_jti": "d4811bf1-2798-4d33-b65c-2f8254729dd2",
        "event_id": "18828d18-b465-470e-84b6-17520ded299b",
        "token_use": "access",
        "scope": "phone openid email",
        "auth_time": 1647961493,
        "exp": 1647965093,
        "iat": 1647961493,
        "jti": "0fe29a9e-6e94-479b-987b-e45696d5843a",
        "username": "mblack",
    }


def test_verify_id_token(mocker, jwks, cfg):
    mocker.patch(
        "jwt.jwks_client.PyJWKClient.get_jwk_set",
        return_value=PyJWKSet.from_dict(jwks),
    )
    serv = TokenService(cfg=cfg)

    token = (
        "eyJraWQiOiJzcHZVVmF0NmNsWFN0cG9JaDZuQ1V0dFQ2eTZBbVBvUEF0eStVTU52UTJZPSIsImFsZyI6IlJTMjU2In0."
        "eyJhdF9oYXNoIjoiV3FUZ0JON3VGUG5uSlJneWQ4NldMQSIsInN1YiI6IjkwNDhkMzhmLTgxNzQtNDliOS04ZDU5LTMyMzgxNzI4MjNkOCIsImNvZ25pdG86Z3JvdXBzIjpbImFkbWluIl0sImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmV1LXdlc3QtMS5hbWF6b25hd3MuY29tXC9ldS13ZXN0LTFfYzdPOTBTTkRGIiwiY29nbml0bzp1c2VybmFtZSI6Im1ibGFjayIsIm5vbmNlIjoiTVNsbjZudlBJSUJWTWhzTlVPdFVDdHNzY2VVS3o0ZGhDUlppNVFaUlU0QT0iLCJvcmlnaW5fanRpIjoiZDQ4MTFiZjEtMjc5OC00ZDMzLWI2NWMtMmY4MjU0NzI5ZGQyIiwiYXVkIjoiNGxsbjY2NzI2cHAzZjRnaTFrcmowc3RhOWgiLCJldmVudF9pZCI6IjE4ODI4ZDE4LWI0NjUtNDcwZS04NGI2LTE3NTIwZGVkMjk5YiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjQ3OTYxNDkzLCJleHAiOjE2NDc5NjUwOTMsImlhdCI6MTY0Nzk2MTQ5MywianRpIjoiMDU0YjhlNjYtNTg1My00MTI3LTlkNTUtZTNhMjlkYmQ4NGJkIiwiZW1haWwiOiJtYmxhY2tAc3BhcmtnZW8uY29tIn0."
        "vnGkFOxtC7ubRkQHByNst5Uyxj4kGFXRP-kaG09iRCADJQSgxwGjZDbG4xbvW0EISA4mGz1sfnCiinuWLNrbKR4KUC3qTytu4hq91OCjB2-KKxeVHxQR1NsjYZ8u7DBOCVeKSouO4oaHDf966f1gubdYXDp12urtiDJy9MybV9diRxOm2eRLAQPIxSFO5owGNcGh03OWystMEJvUwwDVbdpf562OZ72Eo9UHnv3eR3VvH1Gv49WAzwqweIVRiv4-hJqGjLeKnqo3X1toBvU_2QPN9KmM7oYcIpYqagKQNCIcsLq6ZngOJfbCBPCPQX9XYrCkMAmm0VaBRix2zzHYtg"
    )

    claims = serv.verify_id_token(token, leeway=1e9)
    assert claims == {
        "at_hash": "WqTgBN7uFPnnJRgyd86WLA",
        "sub": "9048d38f-8174-49b9-8d59-3238172823d8",
        "cognito:groups": ["admin"],
        "email_verified": False,
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_c7O90SNDF",
        "cognito:username": "mblack",
        "nonce": "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A=",
        "origin_jti": "d4811bf1-2798-4d33-b65c-2f8254729dd2",
        "aud": "4lln66726pp3f4gi1krj0sta9h",
        "event_id": "18828d18-b465-470e-84b6-17520ded299b",
        "token_use": "id",
        "auth_time": 1647961493,
        "exp": 1647965093,
        "iat": 1647961493,
        "jti": "054b8e66-5853-4127-9d55-e3a29dbd84bd",
        "email": "mblack@sparkgeo.com",
    }

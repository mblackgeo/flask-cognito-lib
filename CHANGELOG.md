<!--next-version-placeholder-->

## v1.9.6 (2025-10-09)

### Fix
- Add py.typed marker ([`1ef35ce`](https://github.com/mblackgeo/flask-cognito-lib/commit/1ef35cee22deac4247cb01d497a3000ffb35252b))
- Ensure typing_extensions is added to project dependencies ([`1e8bf57`](https://github.com/mblackgeo/flask-cognito-lib/commit/1e8bf574a0f762f2dab49b081e1ab043a4df558b))
- Drop support for python 3.8 ([`9a45e49`](https://github.com/mblackgeo/flask-cognito-lib/commit/9a45e49a45bec842c4873ca6eb2db514ec04d441))

### Documentation
- Add mypy validation note to README ([`1979383`](https://github.com/mblackgeo/flask-cognito-lib/commit/197938369076a286bc18ba43340df429e31494bf))
- Replace poetry link with uv ([`abe5aa7`](https://github.com/mblackgeo/flask-cognito-lib/commit/abe5aa75d57508233be6ab142946bb147429d717))
- Update README to reflect migration from flake8 and Black to ruff for linting and formatting ([`8273a7f`](https://github.com/mblackgeo/flask-cognito-lib/commit/8273a7f6c400d97d67db115cda238d50af3cf42b))

## v1.9.5 (2025-10-08)

### Fix

* Handle and raise if KeyError rather than possibly cause redirect loop ([`96b9c4e`](https://github.com/mblackgeo/flask-cognito-lib/commit/96b9c4e0ac4f859cbafe6f86e2838ec06715961b))
* Add test for refresh_token method with corrected typo ([`f6d1d1c`](https://github.com/mblackgeo/flask-cognito-lib/commit/f6d1d1cb4bf19ad95f37b5fb3ad88a75ebaf5ce8))
* Reorder import statements to keep isort happy ([`5d47373`](https://github.com/mblackgeo/flask-cognito-lib/commit/5d4737317e34d23a578024152092ea5827d2a831))
* Add error handling for missing session data in cognito_login_callback ([`c803f96`](https://github.com/mblackgeo/flask-cognito-lib/commit/c803f9675368281c6e3b26577abd16fe83a410bb))
* Correct typo in Config class docstring ([`47cec84`](https://github.com/mblackgeo/flask-cognito-lib/commit/47cec84a8b95f14247fd46b7bd26fc241815b61d))
* Correct typo in exchange_refresh_token method name ([`1058136`](https://github.com/mblackgeo/flask-cognito-lib/commit/1058136738cf4563aaf8b2b368e4d3b488a96912))

## v1.9.4 (2025-03-04)

### Fix

* Update cryptography package ([#79](https://github.com/mblackgeo/flask-cognito-lib/issues/79)) ([`2a93d21`](https://github.com/mblackgeo/flask-cognito-lib/commit/2a93d2168a9c4b1ebfba0c1f32782aa3c76c324e))

## v1.9.3 (2024-12-30)

### Fix

* Stricter guards against None values ([#55](https://github.com/mblackgeo/flask-cognito-lib/issues/55)) ([`0184b52`](https://github.com/mblackgeo/flask-cognito-lib/commit/0184b523ad4790e3ff746e4bbd9b7aae105b4bc2))

## v1.9.2 (2024-10-28)

### Fix

* Add null check for cognito groups ([#54](https://github.com/mblackgeo/flask-cognito-lib/issues/54)) ([`d4a0cba`](https://github.com/mblackgeo/flask-cognito-lib/commit/d4a0cbada48f0cd6bc4e48fe93862c821f51acf8))

## v1.9.1 (2024-09-26)

### Fix

* Update cryptography to address GHSA-h4gh-qq45-vh27 ([`39a22bb`](https://github.com/mblackgeo/flask-cognito-lib/commit/39a22bb7ffad2aa3acfc6b16724602bd48235713))

## v1.9.0 (2024-09-23)

### Feature

* Store cognito_id_token in cookie ([#45](https://github.com/mblackgeo/flask-cognito-lib/issues/45)) ([`6933d04`](https://github.com/mblackgeo/flask-cognito-lib/commit/6933d044d9cc08e39cd3665bf85df6a9a202d5a3))

## v1.8.2 (2024-08-27)

### Fix

* Update cryptography pin to address CVE-2024-26130 ([`c37f1e5`](https://github.com/mblackgeo/flask-cognito-lib/commit/c37f1e5b16cb328115158c1ba7b4ca80d69778a3))

## v1.8.1 (2024-07-29)

### Fix

* Add descriptions to HTML exceptions ([#47](https://github.com/mblackgeo/flask-cognito-lib/issues/47)) ([`08e251e`](https://github.com/mblackgeo/flask-cognito-lib/commit/08e251e823b00bda106eba76dacd5896267444b3))

## v1.8.0 (2024-05-30)

### Feature

* Allow overriding of configuration object ([#43](https://github.com/mblackgeo/flask-cognito-lib/issues/43)) ([`ece4645`](https://github.com/mblackgeo/flask-cognito-lib/commit/ece4645a1aea239fddfd15720e68ddf3e9814d28))

## v1.7.0 (2024-05-15)

### Feature

* Add refresh token flow ([#39](https://github.com/mblackgeo/flask-cognito-lib/issues/39)) ([`e165ab8`](https://github.com/mblackgeo/flask-cognito-lib/commit/e165ab827d6e99da1f8416900d1a572625147e49))

## v1.6.2 (2024-03-26)

### Fix

* Support urllib3 2.x ([`ffbd55e`](https://github.com/mblackgeo/flask-cognito-lib/commit/ffbd55eb2f141151d3d0ef4394b445a7aa8cc821))

## v1.6.1 (2023-10-30)

### Fix

* Support flask 2.x and 3.x ([`14f62f5`](https://github.com/mblackgeo/flask-cognito-lib/commit/14f62f5469a96d871bcbca3a8d117011d459dd62))

## v1.6.0 (2023-10-30)
### Feature

* Add support for setting domain and samesite on the cookie ([`46e69c8`](https://github.com/mblackgeo/flask-cognito-lib/commit/46e69c8792c81b251c211b51979f0e0e4105a99a))

### Documentation

* Update with new configuration options for cookie domain/samesite ([`90fd6ac`](https://github.com/mblackgeo/flask-cognito-lib/commit/90fd6ace96a0c0fee275ec2f1f8b08d0e8e2d3e7))
* Remove misleading text in example in README ([`9faafc0`](https://github.com/mblackgeo/flask-cognito-lib/commit/9faafc0bf12bcfc7b0e9fc1cd03ef4944289fb22))

## v1.5.0 (2023-07-12)
### Feature

* Support "any" group membership in `auth_required` decorator ([`7d38fdb`](https://github.com/mblackgeo/flask-cognito-lib/commit/7d38fdb24593f96f66421b7974fe29c0a1e58ae0))

### Documentation

* Fix type in example usage of any group argument ([`bd0b9cc`](https://github.com/mblackgeo/flask-cognito-lib/commit/bd0b9cccb3f6476743cdf63c074e809b78a7ed8b))
* Add examples of "any group" membership ([`8c42686`](https://github.com/mblackgeo/flask-cognito-lib/commit/8c42686bc52336b5feeb8275514a77bca4678ae6))

## v1.4.1 (2023-07-08)
### Fix

* Replace use of deprecated app context stack ([`692f312`](https://github.com/mblackgeo/flask-cognito-lib/commit/692f312e5bb8f34080d44d2aed30ff43926a62b2))

## v1.4.0 (2023-07-08)
### Feature

* Support Public Cognito Clients without an app secret ([#17](https://github.com/mblackgeo/flask-cognito-lib/issues/17)) ([`a54077c`](https://github.com/mblackgeo/flask-cognito-lib/commit/a54077c34ff43c211bea1dcd836daecde58e4fee))

### Documentation

* Fix badges ([`7b73d81`](https://github.com/mblackgeo/flask-cognito-lib/commit/7b73d81f8329aaaa19a96d8282578f2055a962ec))

## v1.3.2 (2023-05-31)
### Fix

* Bump poetry version for CI pipelines ([`c60092c`](https://github.com/mblackgeo/flask-cognito-lib/commit/c60092c6d7a041e8fdb7be29fc770d652dfe98fc))
* Typo in isort configuration ([`8d80de8`](https://github.com/mblackgeo/flask-cognito-lib/commit/8d80de8858bafb298b94249dd4d5d4a80da11120))
* Remove deprecated server_name argument ([`22b10c8`](https://github.com/mblackgeo/flask-cognito-lib/commit/22b10c8e4dbcb66ae9d26f614c419208e9eed806))
* Remove --no-update option ([`7ad415c`](https://github.com/mblackgeo/flask-cognito-lib/commit/7ad415c98c1a25edebb3c9a87c7cfa8545b19a6f))
* Bump poetry version ([`c3558a7`](https://github.com/mblackgeo/flask-cognito-lib/commit/c3558a7ccfeafad6690520eb1f130860f9578296))
* Specify default when extracting session state ([`c28da44`](https://github.com/mblackgeo/flask-cognito-lib/commit/c28da44afaccbc6259f75edf407447afbbf3d12c))

### Documentation

* Fix typo for installation ([`3e0d6cd`](https://github.com/mblackgeo/flask-cognito-lib/commit/3e0d6cd1dfab4155c6682e5d0c34c429ef2a51be))
* Fix badges ([`fc8e167`](https://github.com/mblackgeo/flask-cognito-lib/commit/fc8e1674e8e0a90e2dcf6987d7b43634dd566f32))

## v1.3.1 (2022-07-06)
### Fix
* Run decorators within the app context ([`bb8bd38`](https://github.com/mblackgeo/flask-cognito-lib/commit/bb8bd381ef6a49d39f82babf8a86091e4cd557f3))

### Documentation
* Add SECRET_KEY to required config ([`366c862`](https://github.com/mblackgeo/flask-cognito-lib/commit/366c862f133ebf8f4c4908ded96fbd51ec4f8f4e))
* Fix typo in repo_url for mkdocs ([`b2e0875`](https://github.com/mblackgeo/flask-cognito-lib/commit/b2e08754914f4ffc28795d2288cd72feec858d7b))

## v1.3.0 (2022-05-25)
### Feature
* Bump pyjwt minor version ([`672b99e`](https://github.com/mblackgeo/flask-cognito-lib/commit/672b99eca5d2865ca96e064f21bda68378b25328))

### Documentation
* Fix broken badges on mkdocs ([`9f888f6`](https://github.com/mblackgeo/flask-cognito-lib/commit/9f888f6d37c22c4ac1bb2f96a11b6b69cf63f71f))

## v1.2.0 (2022-05-06)
### Feature
* Add new config parameter to disable extension ([`fcafc51`](https://github.com/mblackgeo/flask-cognito-lib/commit/fcafc510e80ee901885e324d180aed3529fbcdbc))

### Documentation
* Add docs for the AWS_COGNITO_DISABLED parameter ([`26b2439`](https://github.com/mblackgeo/flask-cognito-lib/commit/26b2439078cd9affd1d3fcdff54d195838a92af0))
* Fix typo for cross-site request forgery ([`1af4d24`](https://github.com/mblackgeo/flask-cognito-lib/commit/1af4d241d5b5a7ce8ccfba1748ba9fce06bf22d1))
* Update comment about state value ([`c36ed85`](https://github.com/mblackgeo/flask-cognito-lib/commit/c36ed85bdfdc8e3c866a1971c552c79ced9f1b9f))
* Add extra details about using state value ([`8195ef0`](https://github.com/mblackgeo/flask-cognito-lib/commit/8195ef03e75b39063a68996bdb31f0a8b0e9dd2c))
* Fix broken link ([`26ad95f`](https://github.com/mblackgeo/flask-cognito-lib/commit/26ad95fe2d74259857029fb4f34c45eb71f0f20a))
* Update badges ([`9d93e38`](https://github.com/mblackgeo/flask-cognito-lib/commit/9d93e38eefed0af8a24e167dfa9ad5139badc997))

## v1.1.6 (2022-03-30)


## v1.1.5 (2022-03-30)


## v1.1.4 (2022-03-30)
### Documentation
* Add placeholder for semantic in the Changelog ([`9549891`](https://github.com/mblackgeo/flask-cognito-lib/commit/9549891f0be93b8993b3c7643de8280de2d4f742))

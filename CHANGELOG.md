# Change Log

## [v2.3.0](https://github.com/auth0/auth0-spa-js/tree/v2.3.0) (2025-07-16)
[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.2.0...v2.3.0)

**Fixed**
- Fix: Token Exchange Ignoring Scope and Audience Parameters [\#1365](https://github.com/auth0/auth0-spa-js/pull/1365) ([tusharpandey13](https://github.com/tusharpandey13))
- bugfix: Correctly extract origin from domainUrl [\#1372](https://github.com/auth0/auth0-spa-js/pull/1372) ([tusharpandey13](https://github.com/tusharpandey13))

## [v2.2.0](https://github.com/auth0/auth0-spa-js/tree/v2.2.0) (2025-05-28)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.1.3...v2.2.0)

**Added**

- Custom Token Exchange [\#1344](https://github.com/auth0/auth0-spa-js/pull/1344) ([tusharpandey13](https://github.com/tusharpandey13))

## [v2.1.3](https://github.com/auth0/auth0-spa-js/tree/v2.1.3) (2023-12-11)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.1.2...v2.1.3)

**Changed**

- feat: support for hosted token worker [\#1208](https://github.com/auth0/auth0-spa-js/pull/1208) ([DJMcK](https://github.com/DJMcK))

## [v2.1.2](https://github.com/auth0/auth0-spa-js/tree/v2.1.2) (2023-08-21)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.1.1...v2.1.2)

**Fixed**

- Ensure organization cookie is set when no organization was set [\#1123](https://github.com/auth0/auth0-spa-js/pull/1123) ([frederikprijck](https://github.com/frederikprijck))

## [v2.1.1](https://github.com/auth0/auth0-spa-js/tree/v2.1.1) (2023-07-18)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.1.0...v2.1.1)

**Changed**

- Do not lowercase org_name claim [\#1117](https://github.com/auth0/auth0-spa-js/pull/1117) ([frederikprijck](https://github.com/frederikprijck))

## [v2.1.0](https://github.com/auth0/auth0-spa-js/tree/v2.1.0) (2023-07-13)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.8...v2.1.0)

**Added**

- Support Organization Name [\#1113](https://github.com/auth0/auth0-spa-js/pull/1113) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**

- Ensure AMR claim is set to an array of strings [\#1112](https://github.com/auth0/auth0-spa-js/pull/1112) ([frederikprijck](https://github.com/frederikprijck))

## [v2.0.8](https://github.com/auth0/auth0-spa-js/tree/v2.0.8) (2023-06-14)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.7...v2.0.8)

**Changed**

- Lazily retrieve transaction from transaction storage [\#1108](https://github.com/auth0/auth0-spa-js/pull/1108) ([frederikprijck](https://github.com/frederikprijck))

## [v2.0.7](https://github.com/auth0/auth0-spa-js/tree/v2.0.7) (2023-06-02)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.6...v2.0.7)

**Changed**

- Make TransactionManager use CookieDomain [\#1105](https://github.com/auth0/auth0-spa-js/pull/1105) ([ZdravkoDonev-gtmhub](https://github.com/ZdravkoDonev-gtmhub))

## [v2.0.6](https://github.com/auth0/auth0-spa-js/tree/v2.0.6) (2023-05-30)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.5...v2.0.6)

**Fixed**

- Fix missing invalid state errors with Generic Error [\#1102](https://github.com/auth0/auth0-spa-js/pull/1102) ([frederikprijck](https://github.com/frederikprijck))

## [v2.0.5](https://github.com/auth0/auth0-spa-js/tree/v2.0.5) (2023-05-22)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.4...v2.0.5)

**Changed**

- distinguish between missing and invalid state [\#1099](https://github.com/auth0/auth0-spa-js/pull/1099) ([frederikprijck](https://github.com/frederikprijck))
- Allow sync openUrl [\#1087](https://github.com/auth0/auth0-spa-js/pull/1087) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.0.4](https://github.com/auth0/auth0-spa-js/tree/v2.0.4) (2023-02-22)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.3...v2.0.4)

**Fixed**

- Correctly expose missing_refresh_token error from worker [\#1080](https://github.com/auth0/auth0-spa-js/pull/1080) ([frederikprijck](https://github.com/frederikprijck))

## [v2.0.3](https://github.com/auth0/auth0-spa-js/tree/v2.0.3) (2023-02-04)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.2...v2.0.3)

**Fixed**

- Ensure cookieDomain is used when using legacy Cookiestorage [\#1071](https://github.com/auth0/auth0-spa-js/pull/1071) ([frederikprijck](https://github.com/frederikprijck))
- Ensure to only clear current client cache when logging out [\#1068](https://github.com/auth0/auth0-spa-js/pull/1068) ([frederikprijck](https://github.com/frederikprijck))

## [v2.0.2](https://github.com/auth0/auth0-spa-js/tree/v2.0.2) (2023-01-12)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.1...v2.0.2)

**Security**

- Bump jsonwebtoken to v9 [\#1062](https://github.com/auth0/auth0-spa-js/pull/1062) ([dependabot](https://github.com/apps/dependabot))

This patch release is identical to `2.0.1` but has been released to ensure tooling no longer detects a vulnerable version of `jsonwebtoken` being used.

Even though 2.0.1 was not vulnerable for the related [CVE](https://unit42.paloaltonetworks.com/jsonwebtoken-vulnerability-cve-2022-23529/) because of the fact that `jsonwebtoken` is a devDependency, we are cutting a release to ensure build tools no longer report our SDK as vulnerable to the mentioned CVE.

## [v2.0.1](https://github.com/auth0/auth0-spa-js/tree/v2.0.1) (2022-12-08)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.0...v2.0.1)

**Changed**

- Add openUrl and deprecate onRedirect [\#1058](https://github.com/auth0/auth0-spa-js/pull/1058) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**

- Export MissingRefreshTokenError [\#1043](https://github.com/auth0/auth0-spa-js/pull/1043) ([frederikprijck](https://github.com/frederikprijck))

## [v2.0.0](https://github.com/auth0/auth0-spa-js/tree/v2.0.0) (2022-10-27)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.22.5...v2.0.0)

Auth0-SPA-JS v2 includes many significant changes compared to v1:

- Refactor module output and avoid default export [#942](https://github.com/auth0/auth0-spa-js/pull/942) ([frederikprijck](https://github.com/frederikprijck))
- Do not throw from `checkSession` [#943](https://github.com/auth0/auth0-spa-js/pull/943) ([frederikprijck](https://github.com/frederikprijck))
- Rework `ignoreCache` to `cacheMode` and introduce `cache-only` [#950](https://github.com/auth0/auth0-spa-js/pull/950) ([ewanharris](https://github.com/ewanharris))
- Do not fallback to refreshing tokens via iframe method by default [#946](https://github.com/auth0/auth0-spa-js/pull/946) ([ewanharris](https://github.com/ewanharris))
- Use form-encoded data by default [#945](https://github.com/auth0/auth0-spa-js/pull/945) ([frederikprijck](https://github.com/frederikprijck))
- Remove `getIdTokenClaimsOptions` type [#960](https://github.com/auth0/auth0-spa-js/pull/960) ([ewanharris](https://github.com/ewanharris))
- Rename `client_id` to `clientId` [#956](https://github.com/auth0/auth0-spa-js/pull/956) ([ewanharris](https://github.com/ewanharris))
- Remove polyfills from bundles [#951](https://github.com/auth0/auth0-spa-js/pull/951) ([frederikprijck](https://github.com/frederikprijck))
- Update output target to **ES2017** [#953](https://github.com/auth0/auth0-spa-js/pull/953) ([frederikprijck](https://github.com/frederikprijck))
- Introduce `authorizationParams` to hold properties sent to Auth0 [#959](https://github.com/auth0/auth0-spa-js/pull/959) ([ewanharris](https://github.com/ewanharris))
- Do not build Common JS module with externals [#971](https://github.com/auth0/auth0-spa-js/pull/971) ([frederikprijck](https://github.com/frederikprijck))
- De-dupe Id token; getUser and getIdTokenClaims no longer take any arguments [#967](https://github.com/auth0/auth0-spa-js/pull/967) ([frederikprijck](https://github.com/frederikprijck))
- Remove `advancedOptions.defaultScope` and replace with `scope` [#972](https://github.com/auth0/auth0-spa-js/pull/972) ([ewanharris](https://github.com/ewanharris))
- Cache and return id token from memory [#975](https://github.com/auth0/auth0-spa-js/pull/975) ([ewanharris](https://github.com/ewanharris))
- Remove `buildAuthorizeUrl` [#980](https://github.com/auth0/auth0-spa-js/pull/980) ([frederikprijck](https://github.com/frederikprijck))
- Make `buildLogoutUrl` internal [#982](https://github.com/auth0/auth0-spa-js/pull/982) ([ewanharris](https://github.com/ewanharris))
- Fix spelling mistakes in id token validation messages [#940](https://github.com/auth0/auth0-spa-js/pull/940) ([frederikprijck](https://github.com/frederikprijck))

As with any major version bump, v2 of Auth0-SPA-JS contains a set of breaking changes. **Please review [the migration guide](./MIGRATION_GUIDE.md) thoroughly to understand the changes required to migrate your application to v2.**

## [v2.0.0-beta.1](https://github.com/auth0/auth0-spa-js/tree/v2.0.0-beta.1) (2022-10-12)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v2.0.0-beta.0...v2.0.0-beta.1)

**Fixed**

- Ensure getTokenSilently works when mixing return types [\#1016](https://github.com/auth0/auth0-spa-js/pull/1016) ([frederikprijck](https://github.com/frederikprijck))
- Close MessageChannel after receiving and processing message from worker [\#1023](https://github.com/auth0/auth0-spa-js/pull/1023) ([ewanharris](https://github.com/ewanharris))

## [v2.0.0-beta.0](https://github.com/auth0/auth0-spa-js/tree/v2.0.0-beta.0) (2022-10-01)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.22.5...v2.0.0-beta.0)

Auth0-SPA-JS v2 includes many significant changes compared to v1:

- Refactor module output and avoid default export [#942](https://github.com/auth0/auth0-spa-js/pull/942) ([frederikprijck](https://github.com/frederikprijck))
- Do not throw from `checkSession` [#943](https://github.com/auth0/auth0-spa-js/pull/943) ([frederikprijck](https://github.com/frederikprijck))
- Rework `ignoreCache` to `cacheMode` and introduce `cache-only` [#950](https://github.com/auth0/auth0-spa-js/pull/950) ([ewanharris](https://github.com/ewanharris))
- Do not fallback to refreshing tokens via iframe method by default [#946](https://github.com/auth0/auth0-spa-js/pull/946) ([ewanharris](https://github.com/ewanharris))
- Use form-encoded data by default [#945](https://github.com/auth0/auth0-spa-js/pull/945) ([frederikprijck](https://github.com/frederikprijck))
- Remove `getIdTokenClaimsOptions` type [#960](https://github.com/auth0/auth0-spa-js/pull/960) ([ewanharris](https://github.com/ewanharris))
- Rename `client_id` to `clientId` [#956](https://github.com/auth0/auth0-spa-js/pull/956) ([ewanharris](https://github.com/ewanharris))
- Remove polyfills from bundles [#951](https://github.com/auth0/auth0-spa-js/pull/951) ([frederikprijck](https://github.com/frederikprijck))
- Update output target to **ES2017** [#953](https://github.com/auth0/auth0-spa-js/pull/953) ([frederikprijck](https://github.com/frederikprijck))
- Introduce `authorizationParams` to hold properties sent to Auth0 [#959](https://github.com/auth0/auth0-spa-js/pull/959) ([ewanharris](https://github.com/ewanharris))
- Do not build Common JS module with externals [#971](https://github.com/auth0/auth0-spa-js/pull/971) ([frederikprijck](https://github.com/frederikprijck))
- De-dupe Id token; getUser and getIdTokenClaims no longer take any arguments [#967](https://github.com/auth0/auth0-spa-js/pull/967) ([frederikprijck](https://github.com/frederikprijck))
- Remove `advancedOptions.defaultScope` and replace with `scope` [#972](https://github.com/auth0/auth0-spa-js/pull/972) ([ewanharris](https://github.com/ewanharris))
- Cache and return id token from memory [#975](https://github.com/auth0/auth0-spa-js/pull/975) ([ewanharris](https://github.com/ewanharris))
- Remove `buildAuthorizeUrl` [#980](https://github.com/auth0/auth0-spa-js/pull/980) ([frederikprijck](https://github.com/frederikprijck))
- Make `buildLogoutUrl` internal [#982](https://github.com/auth0/auth0-spa-js/pull/982) ([ewanharris](https://github.com/ewanharris))
- Fix spelling mistakes in id token validation messages [#940](https://github.com/auth0/auth0-spa-js/pull/940) ([frederikprijck](https://github.com/frederikprijck))

As with any major version bump, v2 of Auth0-SPA-JS contains a set of breaking changes. **Please review [the migration guide](./MIGRATION_GUIDE.md) thoroughly to understand the changes required to migrate your application to v2.**

## [v1.22.5](https://github.com/auth0/auth0-spa-js/tree/v1.22.5) (2022-10-12)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.22.4...v1.22.5)

**Fixed**

- Ensure getTokenSilently works when mixing return types [\#1016](https://github.com/auth0/auth0-spa-js/pull/1016) ([frederikprijck](https://github.com/frederikprijck))

## [v1.22.4](https://github.com/auth0/auth0-spa-js/tree/v1.22.4) (2022-09-08)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.22.3...v1.22.4)

**Fixed**

- Release lock on pagehide [\#974](https://github.com/auth0/auth0-spa-js/pull/974) ([frederikprijck](https://github.com/frederikprijck))

## [v1.22.3](https://github.com/auth0/auth0-spa-js/tree/v1.22.3) (2022-08-25)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.22.2...v1.22.3)

**Changed**

- feat(ClientStorage#remove):added support of cookieDomain [\#935](https://github.com/auth0/auth0-spa-js/pull/935) ([Dannnir](https://github.com/Dannnir))

**Fixed**

- Pin es-cookie to patch versions only [\#965](https://github.com/auth0/auth0-spa-js/pull/965) ([frederikprijck](https://github.com/frederikprijck))

## [v1.22.2](https://github.com/auth0/auth0-spa-js/tree/v1.22.2) (2022-07-19)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.22.1...v1.22.2)

**Changed**

- Avoid sending unnecessary request parameters [\#920](https://github.com/auth0/auth0-spa-js/pull/920) ([frederikprijck](https://github.com/frederikprijck))

## [v1.22.1](https://github.com/auth0/auth0-spa-js/tree/v1.22.1) (2022-06-14)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.22.0...v1.22.1)

**Changed**

- Stronger typing for screen_hint property [\#912](https://github.com/auth0/auth0-spa-js/pull/912) ([iAmWillShepherd](https://github.com/iAmWillShepherd))
- Add env to auth0Client userAgent [\#913](https://github.com/auth0/auth0-spa-js/pull/913) ([frederikprijck](https://github.com/frederikprijck))

## [v1.22.0](https://github.com/auth0/auth0-spa-js/tree/v1.22.0) (2022-05-24)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.21.1...v1.22.0)

**Added**

- Silent auth fallback when using Refresh Tokens can now be disabled [\#907](https://github.com/auth0/auth0-spa-js/pull/907) ([frederikprijck](https://github.com/frederikprijck))

**Security**

- [Snyk] Upgrade core-js 3.22.4 [\#910](https://github.com/auth0/auth0-spa-js/pull/910) ([crew-security](https://github.com/crew-security))

## [v1.21.1](https://github.com/auth0/auth0-spa-js/tree/v1.21.1) (2022-05-10)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.21.0...v1.21.1)

**Fixed**

- Organization ID hint cookie now respects `cookieDomain` config setting [\#900](https://github.com/auth0/auth0-spa-js/pull/900) ([Dannnir](https://github.com/Dannnir))

**Security**

- [Snyk] Upgrade core-js from 3.21.1 to 3.22.0 [\#901](https://github.com/auth0/auth0-spa-js/pull/901) ([snyk-bot](https://github.com/snyk-bot))
- [Snyk] Upgrade promise-polyfill from 8.2.1 to 8.2.3 [\#893](https://github.com/auth0/auth0-spa-js/pull/893) ([snyk-bot](https://github.com/snyk-bot))

## [v1.21.0](https://github.com/auth0/auth0-spa-js/tree/v1.21.0) (2022-04-01)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.20.1...v1.21.0)

**Added**

- FEAT override cookie domain option [\#885](https://github.com/auth0/auth0-spa-js/pull/885) ([Soviut](https://github.com/Soviut))

**Fixed**

- fix: handle NPE when no popup is available [\#888](https://github.com/auth0/auth0-spa-js/pull/888) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.20.1](https://github.com/auth0/auth0-spa-js/tree/v1.20.1) (2022-03-04)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.20.0...v1.20.1)

**Fixed**

- Prevent cache.get when key is undefined [\#882](https://github.com/auth0/auth0-spa-js/pull/882) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.20.0](https://github.com/auth0/auth0-spa-js/tree/v1.20.0) (2022-02-14)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.19.4...v1.20.0)

**Added**

- [SDK-3105] Add httpTimeoutInSeconds to control fetch timeout [\#875](https://github.com/auth0/auth0-spa-js/pull/875) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Changed**

- clarify documentation comment for getTokenSilently [\#874](https://github.com/auth0/auth0-spa-js/pull/874) ([jdugan1024](https://github.com/jdugan1024))

**Fixed**

- Fix getTokenSilently reference in example code [\#868](https://github.com/auth0/auth0-spa-js/pull/868) ([mdlavin](https://github.com/mdlavin))

**Security**

- [Snyk] Upgrade core-js from 3.20.2 to 3.20.3 [\#873](https://github.com/auth0/auth0-spa-js/pull/873) ([snyk-bot](https://github.com/snyk-bot))
- Bump node-fetch from 2.6.1 to 2.6.7 [\#870](https://github.com/auth0/auth0-spa-js/pull/870) ([dependabot[bot]](https://github.com/apps/dependabot))
- [Snyk] Upgrade core-js from 3.20.1 to 3.20.2 [\#869](https://github.com/auth0/auth0-spa-js/pull/869) ([snyk-bot](https://github.com/snyk-bot))
- [Snyk] Upgrade core-js from 3.20.0 to 3.20.1 [\#864](https://github.com/auth0/auth0-spa-js/pull/864) ([snyk-bot](https://github.com/snyk-bot))

## [v1.19.4](https://github.com/auth0/auth0-spa-js/tree/v1.19.4) (2022-01-14)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.19.3...v1.19.4)

**Fixed**

- Org ID hint cookie expiry now aligns with is.authenticated cookie [\#861](https://github.com/auth0/auth0-spa-js/pull/861) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Security**

- Bump follow-redirects from 1.14.0 to 1.14.7 [\#860](https://github.com/auth0/auth0-spa-js/pull/860) ([dependabot[bot]](https://github.com/apps/dependabot))
- [Snyk] Upgrade core-js from 3.19.2 to 3.20.0 [\#858](https://github.com/auth0/auth0-spa-js/pull/858) ([snyk-bot](https://github.com/snyk-bot))
- [Snyk] Upgrade core-js from 3.19.1 to 3.19.2 [\#851](https://github.com/auth0/auth0-spa-js/pull/851) ([snyk-bot](https://github.com/snyk-bot))

## [v1.19.3](https://github.com/auth0/auth0-spa-js/tree/v1.19.3) (2021-12-01)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.19.2...v1.19.3)

**Changed**

- Make RedirectLoginOptions and RedirectLoginResult accept generic AppState [\#846](https://github.com/auth0/auth0-spa-js/pull/846) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**

- Getidtokenclaims return type [\#844](https://github.com/auth0/auth0-spa-js/pull/844) ([jmac105](https://github.com/jmac105))
- Add check for state in handleRedirectCallback [\#841](https://github.com/auth0/auth0-spa-js/pull/841) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Prevent nowProvider from being passed to authorize endpoint [\#840](https://github.com/auth0/auth0-spa-js/pull/840) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Fix cached scopes when using detailed response mode [\#824](https://github.com/auth0/auth0-spa-js/pull/824) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.19.2](https://github.com/auth0/auth0-spa-js/tree/v1.19.2) (2021-10-18)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.19.1...v1.19.2)

This release fixes an anomoly with a new type we exposed in [\#803](https://github.com/auth0/auth0-spa-js/pull/820), where it was incorrectly wrapped with `Partial`. We don't expect this change to introduce any issues, but if you are affected please [raise it on our issue tracker](https://github.com/auth0/auth0-spa-js/issues).

**Fixed**

- GetTokenSilentlyVerboseResponse no longer uses partial TokenEndpointResponse type [\#820](https://github.com/auth0/auth0-spa-js/pull/820) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.19.1](https://github.com/auth0/auth0-spa-js/tree/v1.19.1) (2021-10-14)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.19.0...v1.19.1)

Republished version `1.19.0`, which got published during a period npm was suffering downtime issues, resulting in `1.19.0` being released but not installable for end users. Users should install `1.19.1` instead.

## [v1.19.0](https://github.com/auth0/auth0-spa-js/tree/v1.19.0) (2021-10-11)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.18.0...v1.19.0)

**Added**

- [SDK-2794] Return token response in getTokenSilently [\#803](https://github.com/auth0/auth0-spa-js/pull/803) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-2793] Ability to define a custom now provider [\#802](https://github.com/auth0/auth0-spa-js/pull/802) ([frederikprijck](https://github.com/frederikprijck))

## [v1.18.0](https://github.com/auth0/auth0-spa-js/tree/v1.18.0) (2021-09-15)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.17.1...v1.18.0)

**Added**

- [SDK-2750] Expose mfa_token from the mfa_required error when getting new tokens [\#789](https://github.com/auth0/auth0-spa-js/pull/789) ([frederikprijck](https://github.com/frederikprijck))

**Changed**

- [SDK-2759] Re-scoping cookies and transactions to client ID [\#796](https://github.com/auth0/auth0-spa-js/pull/796) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-2320] Throw login_required error in SPA SDK if running in a cross-origin is… [\#790](https://github.com/auth0/auth0-spa-js/pull/790) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**

- [SDK-2692] Remember organization ID for silent authentication [\#788](https://github.com/auth0/auth0-spa-js/pull/788) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.17.1](https://github.com/auth0/auth0-spa-js/tree/v1.17.1) (2021-09-03)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.17.0...v1.17.1)

**Fixed**

- Correct cache interface [\#779](https://github.com/auth0/auth0-spa-js/pull/779) ([employee451](https://github.com/employee451))

## [v1.17.0](https://github.com/auth0/auth0-spa-js/tree/v1.17.0) (2021-08-03)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.16.1...v1.17.0)

**Added**

- Add `useFormData` to enable `application/x-www-form-urlencoded` requests [\#768](https://github.com/auth0/auth0-spa-js/pull/768) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Changed**

- Allow providing a `domain` that includes `http` or `https`. [\#768](https://github.com/auth0/auth0-spa-js/pull/768) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.16.1](https://github.com/auth0/auth0-spa-js/tree/v1.16.1) (2021-07-07)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.16.0...v1.16.1)

**Fixed**

- Changes to logout and cache synchronicity [\#758](https://github.com/auth0/auth0-spa-js/pull/758) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.16.0](https://github.com/auth0/auth0-spa-js/tree/v1.16.0) (2021-07-05)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.15.0...v1.16.0)

**Added**

- [SDK-2555] Extensible Cache [\#743](https://github.com/auth0/auth0-spa-js/pull/743) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.15.0](https://github.com/auth0/auth0-spa-js/tree/v1.15.0) (2021-04-29)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.14.0...v1.15.0)

**Added**

- Add Popup cancelled event [\#724](https://github.com/auth0/auth0-spa-js/pull/724) ([degrammer](https://github.com/degrammer))

**Fixed**

- Fix popup blocker showing for loginWithPopup in Firefox & Safari [\#732](https://github.com/auth0/auth0-spa-js/pull/732) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.14.0](https://github.com/auth0/auth0-spa-js/tree/v1.14.0) (2021-03-22)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.13.6...v1.14.0)

**Added**

- feat(loginWithRedirect): add redirectMethod option [\#717](https://github.com/auth0/auth0-spa-js/pull/717) ([slaywell](https://github.com/slaywell))
- Export errors for type checking [\#716](https://github.com/auth0/auth0-spa-js/pull/716) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Changed**

- Add screen_hint parameter to BaseLoginOptions [\#721](https://github.com/auth0/auth0-spa-js/pull/721) ([damieng](https://github.com/damieng))

**Fixed**

- Updated minor syntax, to allow for TypeScript compiler to be happier [\#714](https://github.com/auth0/auth0-spa-js/pull/714) ([kachihro](https://github.com/kachihro))
- Revert [SDK-2183] Add warning when requested scopes differ from retrieved scopes [\#712](https://github.com/auth0/auth0-spa-js/pull/712) ([frederikprijck](https://github.com/frederikprijck))

## [v1.13.6](https://github.com/auth0/auth0-spa-js/tree/v1.13.6) (2021-01-07)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.13.5...v1.13.6)

**Changed**

- Update docs for getIdTokenClaims and getUser [\#690](https://github.com/auth0/auth0-spa-js/pull/690) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-2238] Only use timeout promise when using fetchWithTimeout without a worker [\#689](https://github.com/auth0/auth0-spa-js/pull/689) ([frederikprijck](https://github.com/frederikprijck))
- Do not use AbortController in the worker if not available [\#679](https://github.com/auth0/auth0-spa-js/pull/679) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Do not send useCookiesForTransactions to authorize request [\#673](https://github.com/auth0/auth0-spa-js/pull/673) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**

- Remove the nonce check in handleRedirectCallback [\#678](https://github.com/auth0/auth0-spa-js/pull/678) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Security**

- Update wait-on to solve security vulnerability [\#687](https://github.com/auth0/auth0-spa-js/pull/687) ([frederikprijck](https://github.com/frederikprijck))
- [Security] Bump ini from 1.3.5 to 1.3.7 [\#672](https://github.com/auth0/auth0-spa-js/pull/672) ([dependabot-preview[bot]](https://github.com/apps/dependabot-preview))

## [v1.13.5](https://github.com/auth0/auth0-spa-js/tree/v1.13.5) (2020-12-08)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.13.4...v1.13.5)

**Changed**

- [SDK-2173] Expand on behaviour of checkSession in docs [\#666](https://github.com/auth0/auth0-spa-js/pull/666) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-2183] Add warning when requested scopes differ from retrieved scopes [\#665](https://github.com/auth0/auth0-spa-js/pull/665) ([frederikprijck](https://github.com/frederikprijck))
- [SDK-2170] Avoid the possibility to do simultaneous calls to the token endpoint [\#664](https://github.com/auth0/auth0-spa-js/pull/664) ([frederikprijck](https://github.com/frederikprijck))
- [SDK-2025] Internal module refactor [\#661](https://github.com/auth0/auth0-spa-js/pull/661) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-2039] Change cache lookup mechanism [\#652](https://github.com/auth0/auth0-spa-js/pull/652) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**

- [SDK-1739] Recover and logout when throwing invalid_grant on Refresh Token [\#668](https://github.com/auth0/auth0-spa-js/pull/668) ([frederikprijck](https://github.com/frederikprijck))

**Remarks**

This release updates the `getUser` return type to be more correct. Instead of returning `Promise<TUser>`, it now returns `Promise<TUser | undefined>`, which might lead to an `Object is possible 'undefined'` compiler error in situation where the return value is not checked for being undefined while having set the TypeScript's `--strictNullChecks` compiler flag to `true`.

## [v1.13.4](https://github.com/auth0/auth0-spa-js/tree/v1.13.4) (2020-12-02)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.13.3...v1.13.4)

**Added**

- [SDK-2172] Add SDK metrics to all API calls [\#659](https://github.com/auth0/auth0-spa-js/pull/659) ([frederikprijck](https://github.com/frederikprijck))

**Changed**

- [SDK-1159] Use generics for getUser [\#651](https://github.com/auth0/auth0-spa-js/pull/651) ([frederikprijck](https://github.com/frederikprijck))

## [v1.13.3](https://github.com/auth0/auth0-spa-js/tree/v1.13.3) (2020-11-13)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.13.2...v1.13.3)

**Fixed**

- [SDK-2156] Heed timeoutInSeconds when calling getTokenSilently with refresh tokens [\#639](https://github.com/auth0/auth0-spa-js/pull/639) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.13.2](https://github.com/auth0/auth0-spa-js/tree/v1.13.2) (2020-11-09)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.13.1...v1.13.2)

**Added**

- [SDK-2121] Add support for token validation for Organizations [\#631](https://github.com/auth0/auth0-spa-js/pull/631) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.13.1](https://github.com/auth0/auth0-spa-js/tree/v1.13.1) (2020-10-29)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.13.0...v1.13.1)

**Changed**

- [SDK-2037] Remove cacheLocation guard from checkSession [\#613](https://github.com/auth0/auth0-spa-js/pull/613) ([frederikprijck](https://github.com/frederikprijck))
- [SDK-2092] Do not use Web Worker for Safari < 12.1 [\#612](https://github.com/auth0/auth0-spa-js/pull/612) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**

- Fix leaking windows message event listener [\#422](https://github.com/auth0/auth0-spa-js/pull/422) ([yinzara](https://github.com/yinzara))

## [v1.13.0](https://github.com/auth0/auth0-spa-js/tree/v1.13.0) (2020-10-21)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.12.1...v1.13.0)

**Added**

- [SDK-2042] Fallback option for transactions using cookies [\#603](https://github.com/auth0/auth0-spa-js/pull/603) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Refactor logout to use buildLogoutUrl [\#595](https://github.com/auth0/auth0-spa-js/pull/595) ([rnwolfe](https://github.com/rnwolfe))
- Add an option to extend cookie expire day [\#586](https://github.com/auth0/auth0-spa-js/pull/586) ([luisfmsouza](https://github.com/luisfmsouza))

**Fixed**

- Use AbortController polyfill in Web Worker [\#598](https://github.com/auth0/auth0-spa-js/pull/598) ([frederikprijck](https://github.com/frederikprijck))
- [SDK-1994] GMaps breaks SPA JS on IE11 [\#592](https://github.com/auth0/auth0-spa-js/pull/592) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.12.1](https://github.com/auth0/auth0-spa-js/tree/v1.12.1) (2020-09-17)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.12.0...v1.12.1)

**Fixed**

- Remove `sessionStorage` requirement from instantiation to fix SSR environments [\#578](https://github.com/auth0/auth0-spa-js/pull/578) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.12.0](https://github.com/auth0/auth0-spa-js/tree/v1.12.0) (2020-09-04)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.11.0...v1.12.0)

**Added**

- [SDK-1858] Create legacy samsite cookie by default [\#568](https://github.com/auth0/auth0-spa-js/pull/568) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Changed**

- Dependency updates [\#569](https://github.com/auth0/auth0-spa-js/pull/569) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Update FAQ.md with information on silent authentication problems [\#550](https://github.com/auth0/auth0-spa-js/pull/550) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Fixed**

- [SDK-1837] Session storage support for transactions [\#564](https://github.com/auth0/auth0-spa-js/pull/564) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-1924] client methods should handle partially filled arguments [\#561](https://github.com/auth0/auth0-spa-js/pull/561) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-1885] Add some additional state validation [\#560](https://github.com/auth0/auth0-spa-js/pull/560) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-1912] Unnecessary latency in `getTokenSilently` with primed cache [\#558](https://github.com/auth0/auth0-spa-js/pull/558) ([adamjmcgrath](https://github.com/adamjmcgrath))
- fix: add missing types to utils.ts and errors.ts [\#547](https://github.com/auth0/auth0-spa-js/pull/547) ([SeyyedKhandon](https://github.com/SeyyedKhandon))
- Exclude windows absolute paths as well as posix [\#534](https://github.com/auth0/auth0-spa-js/pull/534) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.11.0](https://github.com/auth0/auth0-spa-js/tree/v1.11.0) (2020-07-21)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.10.0...v1.11.0)

**Added**

- [SDK-1560] Allow issuer as url [\#523](https://github.com/auth0/auth0-spa-js/pull/523) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-1790] use refresh_tokens with multiple audiences [\#521](https://github.com/auth0/auth0-spa-js/pull/521) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-1650] Add `message` to errors that don't have one [\#520](https://github.com/auth0/auth0-spa-js/pull/520) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- [SDK-1798] prevent unnecessary token requests [\#525](https://github.com/auth0/auth0-spa-js/pull/525) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-1789] Add custom initial options to the 2 getToken methods [\#524](https://github.com/auth0/auth0-spa-js/pull/524) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.10.0](https://github.com/auth0/auth0-spa-js/tree/v1.10.0) (2020-06-17)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.9.0...v1.10.0)

**Changed**

- [SDK-1696] Allow caller of cache.get to specify an expiry time adjustment [\#491](https://github.com/auth0/auth0-spa-js/pull/491) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Fixed**

- Don't include mocks in build [\#503](https://github.com/auth0/auth0-spa-js/pull/503) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-1699] Fix ID token validation for auth_time [\#497](https://github.com/auth0/auth0-spa-js/pull/497) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Add secure attribute to cookies if served over HTTPS [\#472](https://github.com/auth0/auth0-spa-js/pull/472) ([ties-v](https://github.com/ties-v))

## [v1.9.0](https://github.com/auth0/auth0-spa-js/tree/v1.9.0) (2020-06-02)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.8.2...v1.9.0)

**Added**

- [SDK-1695] Add `auth0Client` option so wrapper libraries can send their own client info [\#490](https://github.com/auth0/auth0-spa-js/pull/490) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add `checkSession` and ignore recoverable errors [\#482](https://github.com/auth0/auth0-spa-js/pull/482) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- Update docs for returnTo and client_id params on logout [\#484](https://github.com/auth0/auth0-spa-js/pull/484) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.8.2](https://github.com/auth0/auth0-spa-js/tree/v1.8.2) (2020-05-26)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.8.1...v1.8.2)

**Fixed**

- [SDK-1640] Allow the client to be constructed in a Node SSR environment [\#471](https://github.com/auth0/auth0-spa-js/pull/471) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-1634] Pass custom options to the token endpoint [\#465](https://github.com/auth0/auth0-spa-js/pull/465) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-1649] Fix issue where cache was missed when scope parameter was provided [\#461](https://github.com/auth0/auth0-spa-js/pull/461) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.8.1](https://github.com/auth0/auth0-spa-js/tree/v1.8.1) (2020-05-06)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.8.0...v1.8.1)

**Fixed**

- Fix issue with create-react-app webpack build [\#451](https://github.com/auth0/auth0-spa-js/pull/451) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.8.0](https://github.com/auth0/auth0-spa-js/tree/v1.8.0) (2020-04-30)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.7.0...v1.8.0)

**Added**

- [SDK-1417] Customizable default scopes [\#435](https://github.com/auth0/auth0-spa-js/pull/435) ([stevehobbsdev](https://github.com/stevehobbsdev))
- include polyfill for Set [\#426](https://github.com/auth0/auth0-spa-js/pull/426) ([tony-aq](https://github.com/tony-aq))

**Fixed**

- Update rollup-plugin-web-worker-loader to 1.1.1 [\#443](https://github.com/auth0/auth0-spa-js/pull/443) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Updated `login_hint` js docs to clarify usage with Lock [\#441](https://github.com/auth0/auth0-spa-js/pull/441) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.7.0](https://github.com/auth0/auth0-spa-js/tree/v1.7.0) (2020-04-15)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.7.0-beta.5...v1.7.0)

**Added**

- Support for rotating refresh tokens [\#315](https://github.com/auth0/auth0-spa-js/pull/315) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Export types from global TypeScript file. [\#310](https://github.com/auth0/auth0-spa-js/pull/310) ([maxswa](https://github.com/maxswa))
- Local Storage caching mechanism [\#303](https://github.com/auth0/auth0-spa-js/pull/303) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Changed**

- Use Web Workers for token endpoint call for in-memory storage [\#409](https://github.com/auth0/auth0-spa-js/pull/409) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Export constructor [\#385](https://github.com/auth0/auth0-spa-js/pull/385) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Fall back to iframe method if no refresh token is available [\#364](https://github.com/auth0/auth0-spa-js/pull/364) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Removed setTimeout cache removal in favour of removal-on-read [\#354](https://github.com/auth0/auth0-spa-js/pull/354) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Stop checking `isAuthenticated` cookie on initialization when using local storage [\#352](https://github.com/auth0/auth0-spa-js/pull/352) ([stevehobbsdev](https://github.com/stevehobbsdev))
- getTokenSilently retry logic [\#336](https://github.com/auth0/auth0-spa-js/pull/336) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Fixed issue with cache not retaining refresh token [\#333](https://github.com/auth0/auth0-spa-js/pull/333) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Fixed**

- Check if source of event exists before closing it [\#410](https://github.com/auth0/auth0-spa-js/pull/410) ([gerritdeperrit](https://github.com/gerritdeperrit))
- Check if iframe is still in body before removing [\#399](https://github.com/auth0/auth0-spa-js/pull/399) ([paulfalgout](https://github.com/paulfalgout))
- Fix typings to allow custom claims in ID token [\#386](https://github.com/auth0/auth0-spa-js/pull/386) ([picosam](https://github.com/picosam))
- Fix error in library type definitions [\#367](https://github.com/auth0/auth0-spa-js/pull/367) ([devoto13](https://github.com/devoto13))

**Security**

- Dependency upgrade [\#405](https://github.com/auth0/auth0-spa-js/pull/405) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.7.0-beta.5](https://github.com/auth0/auth0-spa-js/tree/v1.7.0-beta.5) (2020-03-26)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.7.0-beta.4...v1.7.0-beta.5)

**Changed**

- [SDK-1379] Export constructor [\#385](https://github.com/auth0/auth0-spa-js/pull/385) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.7.0-beta.4](https://github.com/auth0/auth0-spa-js/tree/v1.7.0-beta.4) (2020-03-03)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.7.0-beta.3...v1.7.0-beta.4)

**Changed**

- [SDK-1386] Fall back to iframe method if no refresh token is available [\#364](https://github.com/auth0/auth0-spa-js/pull/364) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Fixed**

- Fix error in library type definitions [\#367](https://github.com/auth0/auth0-spa-js/pull/367) ([devoto13](https://github.com/devoto13))

## [v1.7.0-beta.3](https://github.com/auth0/auth0-spa-js/tree/v1.7.0-beta.3) (2020-02-17)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.7.0-beta.2...v1.7.0-beta.3)

**Added**

- Export types from global TypeScript file. [\#310](https://github.com/auth0/auth0-spa-js/pull/310) ([maxswa](https://github.com/maxswa))

**Changed**

- [SDK-1352] Removed setTimeout cache removal in favour of removal-on-read [\#354](https://github.com/auth0/auth0-spa-js/pull/354) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-1352] Stop checking `isAuthenticated` cookie on initialization when using local storage [\#352](https://github.com/auth0/auth0-spa-js/pull/352) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-1279] getTokenSilently retry logic [\#336](https://github.com/auth0/auth0-spa-js/pull/336) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.7.0-beta.2](https://github.com/auth0/auth0-spa-js/tree/v1.7.0-beta.2) (2020-01-16)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.7.0-beta.1...v1.7.0-beta.2)

**Changed**

- Fixed issue with cache not retaining refresh token [\#333](https://github.com/auth0/auth0-spa-js/pull/333) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.7.0-beta.1](https://github.com/auth0/auth0-spa-js/tree/v1.7.0-beta.1) (2020-01-08)

**Added**

- Ability to use either an in-memory cache (the default) or localstorage to store tokens - [stevehobbsdev](https://github.com/stevehobbsdev) - https://github.com/auth0/auth0-spa-js/pull/303
- Added support for rotating refresh tokens - [stevehobbsdev](https://github.com/stevehobbsdev) - https://github.com/auth0/auth0-spa-js/pull/315

## [v1.6.5](https://github.com/auth0/auth0-spa-js/tree/v1.6.5) (2020-03-19)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.6.4...v1.6.5)

**Changed**

- [SDK-1395] Refactor loginWithPopup to optionally accept an existing popup window [\#368](https://github.com/auth0/auth0-spa-js/pull/368) ([stevehobbsdev](https://github.com/stevehobbsdev))
- handleRedirectCallback wont pass redirect_uri undefined if not set in transaction [\#374](https://github.com/auth0/auth0-spa-js/pull/374) ([albertlockett](https://github.com/albertlockett))
- Update dependencies within semver ranges [\#371](https://github.com/auth0/auth0-spa-js/pull/371) ([stevehobbsdev](https://github.com/stevehobbsdev))
- [SDK-1099] Add `localOnly` logout option [\#362](https://github.com/auth0/auth0-spa-js/pull/362) ([adamjmcgrath](https://github.com/adamjmcgrath))
- center popup over owner window [\#356](https://github.com/auth0/auth0-spa-js/pull/356) ([ggascoigne](https://github.com/ggascoigne))

**Fixed**

- [SDK-1127] Delay removal of iframe to prevent Chrome hanging status bug #240 [\#376](https://github.com/auth0/auth0-spa-js/pull/376) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-1125] createAuth0Client now throws errors that are not login_required [\#369](https://github.com/auth0/auth0-spa-js/pull/369) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.6.4](https://github.com/auth0/auth0-spa-js/tree/v1.6.4) (2020-02-10)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.6.3...v1.6.4)

**Changed**

- [SDK-1308] Return appState value on error from handleRedirectCallback [\#348](https://github.com/auth0/auth0-spa-js/pull/348) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Configurable timeout for getTokenSilently() [\#347](https://github.com/auth0/auth0-spa-js/pull/347) ([Serjlee](https://github.com/Serjlee))

## [v1.6.3](https://github.com/auth0/auth0-spa-js/tree/v1.6.3) (2020-01-28)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.6.2...v1.6.3)

**Fixed**

- Send same redirect_uri as /authorize to /token [\#341](https://github.com/auth0/auth0-spa-js/pull/341) ([stevehobbsdev](https://github.com/stevehobbsdev))
- No longer acquires a browser lock if there was a hit on the cache [\#339](https://github.com/auth0/auth0-spa-js/pull/339) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Use user provided params on silent login [\#318](https://github.com/auth0/auth0-spa-js/pull/318) ([nkete](https://github.com/nkete))

## [v1.6.2](https://github.com/auth0/auth0-spa-js/tree/v1.6.2) (2020-01-13)

[Full Changelog](https://github.com/auth0/auth0-spa-js/compare/v1.6.1...v1.6.2)

**Removed**

Removed future issued-at claim check [stevehobbsdev](https://github.com/stevehobbsdev) - https://github.com/auth0/auth0-spa-js/pull/329

## [v1.6.1](https://github.com/auth0/auth0-spa-js/tree/v1.6.1) (2020-01-07)

**Fixed**

Included core-js polyfill for `String.includes` to fix an issue with browser-tabs-lock in IE11 [stevehobbsdev](https://github.com/stevehobbsdev) - https://github.com/auth0/auth0-spa-js/pull/325
Added import definition to Getting Started section in the Readme for clarity [thundermiracle](https://github.com/thundermiracle) - https://github.com/auth0/auth0-spa-js/pull/294

## [v1.6.0](https://github.com/auth0/auth0-spa-js/tree/v1.6.0) (2019-11-19)

**Added**
Added buildAuthorizeUrl and url parameter to handleRedirectCallback - [austin43](https://github.com/austin43) - https://github.com/auth0/auth0-spa-js/pull/280

**Fixed**
Released browser lock on getTokenSilently error - https://github.com/auth0/auth0-spa-js/pull/276
Updates browser-tabs-lock to fix issue of long acquired lock - [super-tokens](https://github.com/super-tokens) - https://github.com/auth0/auth0-spa-js/commit/3413e30bdb5955c818989cdc050079fa6efb6050

## [v1.5.0](https://github.com/auth0/auth0-spa-js/tree/v1.5.0) (2019-10-31)

**Added**
Add a new property 'fragment' to be appended to the authorize URL on redirect - https://github.com/auth0/auth0-spa-js/pull/249

## [v1.4.2](https://github.com/auth0/auth0-spa-js/tree/v1.4.2) (2019-10-30)

**Fixed**
Update typescript definition for max_age param - https://github.com/auth0/auth0-spa-js/pull/260
Fix for typings files in packaged SDK - https://github.com/auth0/auth0-spa-js/pull/263

## [v1.4.1](https://github.com/auth0/auth0-spa-js/tree/v1.4.1) (2019-10-30)

**Fixed**
Updated types path in package.json https://github.com/auth0/auth0-spa-js/pull/261

## [v1.4.0](https://github.com/auth0/auth0-spa-js/tree/v1.4.0) (2019-10-30)

**Added**
Add 'lock' to prevent `getTokenSilently` to be invoked in parallel https://github.com/auth0/auth0-spa-js/pull/238
Improved OIDC compliance https://github.com/auth0/auth0-spa-js/pull/248

**Fixed**
Fix for race condition when using `sha256` on IE11 https://github.com/auth0/auth0-spa-js/pull/252
Fixed the codeowners file with the correct group https://github.com/auth0/auth0-spa-js/pull/253
Document leeway default value https://github.com/auth0/auth0-spa-js/pull/256
Clear transaction data on error https://github.com/auth0/auth0-spa-js/pull/254

## [v1.3.2](https://github.com/auth0/auth0-spa-js/tree/v1.3.2) (2019-10-17)

**Fixed**
`parseQueryString` now removes hash fragment on query before parsing https://github.com/auth0/auth0-spa-js/pull/246

## [v1.3.1](https://github.com/auth0/auth0-spa-js/tree/v1.3.1) (2019-10-14)

**Fixed**
Fix IE msCrypto.subtle usage https://github.com/auth0/auth0-spa-js/pull/242

## [v1.3.0](https://github.com/auth0/auth0-spa-js/tree/v1.3.0) (2019-10-10)

**Fixed**
Add missing char for nonce/state generation https://github.com/auth0/auth0-spa-js/pull/230
Fix query parsing when using hash routing https://github.com/auth0/auth0-spa-js/pull/231
Fix safari10 initialization error https://github.com/auth0/auth0-spa-js/pull/232

**Changed**
Add early expiration of Access Token in cache https://github.com/auth0/auth0-spa-js/pull/233

## [v1.2.4](https://github.com/auth0/auth0-spa-js/tree/v1.2.4) (2019-09-24)

**Fixed**

Fix empty PKCE code challenge https://github.com/auth0/auth0-spa-js/pull/221

## [v1.2.3](https://github.com/auth0/auth0-spa-js/tree/v1.2.3) (2019-09-02)

**Fixed**

Fix incorrect state extraction from query string https://github.com/auth0/auth0-spa-js/pull/197

## [v1.2.2](https://github.com/auth0/auth0-spa-js/tree/v1.2.2) (2019-08-28)

**Fixed**

Fix SSR errors with fetch polyfill usage https://github.com/auth0/auth0-spa-js/pull/184

## [v1.2.1](https://github.com/auth0/auth0-spa-js/tree/v1.2.1) (2019-08-27)

**Fixed**

Replace promise polyfill for a pure one. This fixes using this library with zone.js. https://github.com/auth0/auth0-spa-js/pull/180

## [v1.2.0](https://github.com/auth0/auth0-spa-js/tree/v1.2.0) (2019-08-26)

**Fixed**

- Expose raw id_token in the getIdTokenClaims method https://github.com/auth0/auth0-spa-js/pull/175
- Fix bug where oauth/token call ignores `options.audience` https://github.com/auth0/auth0-spa-js/pull/134

**Added**

- Add IE11 polyfills https://github.com/auth0/auth0-spa-js/pull/154
- Add popup timeout config https://github.com/auth0/auth0-spa-js/pull/133
- Add ?federated logout param https://github.com/auth0/auth0-spa-js/pull/129

## [v1.1.1](https://github.com/auth0/auth0-spa-js/tree/v1.1.1) (2019-07-22)

**Fixed**

- Make sure the production bundle is ES5 compatible. https://github.com/auth0/auth0-spa-js/pull/98

## [v1.1.0](https://github.com/auth0/auth0-spa-js/tree/v1.1.0) (2019-07-15)

**Changed**

- Allow redirect_uri override in loginWithRedirect - https://github.com/auth0/auth0-spa-js/pull/66
- Make options argument for popup and redirect optional - https://github.com/auth0/auth0-spa-js/pull/61
- Mark redirect_uri optional in RedirectLoginOptions - https://github.com/auth0/auth0-spa-js/pull/53

## [v1.0.2](https://github.com/auth0/auth0-spa-js/tree/v1.0.2) (2019-07-02)

**Changed**

- Add polyfill for TextEncoder - https://github.com/auth0/auth0-spa-js/pull/46

## [v1.0.1](https://github.com/auth0/auth0-spa-js/tree/v1.0.1) (2019-06-24)

**Changed**

- Reduce transaction cookie size - https://github.com/auth0/auth0-spa-js/pull/32

## [v1.0.0](https://github.com/auth0/auth0-spa-js/tree/v1.0.0) (2019-06-19)

**Initial Release**

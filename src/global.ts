import { ICache } from './cache';

export interface AuthorizationParams {
  /**
   * - `'page'`: displays the UI with a full page view
   * - `'popup'`: displays the UI with a popup window
   * - `'touch'`: displays the UI in a way that leverages a touch interface
   * - `'wap'`: displays the UI with a "feature phone" type interface
   */
  display?: 'page' | 'popup' | 'touch' | 'wap';

  /**
   * - `'none'`: do not prompt user for login or consent on reauthentication
   * - `'login'`: prompt user for reauthentication
   * - `'consent'`: prompt user for consent before processing request
   * - `'select_account'`: prompt user to select an account
   */
  prompt?: 'none' | 'login' | 'consent' | 'select_account';

  /**
   * Maximum allowable elapsed time (in seconds) since authentication.
   * If the last time the user authenticated is greater than this value,
   * the user must be reauthenticated.
   */
  max_age?: string | number;

  /**
   * The space-separated list of language tags, ordered by preference.
   * For example: `'fr-CA fr en'`.
   */
  ui_locales?: string;

  /**
   * Previously issued ID Token.
   */
  id_token_hint?: string;

  /**
   * Provides a hint to Auth0 as to what flow should be displayed.
   * The default behavior is to show a login page but you can override
   * this by passing 'signup' to show the signup page instead.
   *
   * This only affects the New Universal Login Experience.
   */
  screen_hint?: 'signup' | 'login' | string;

  /**
   * The user's email address or other identifier. When your app knows
   * which user is trying to authenticate, you can provide this parameter
   * to pre-fill the email box or select the right session for sign-in.
   *
   * This currently only affects the classic Lock experience.
   */
  login_hint?: string;

  acr_values?: string;

  /**
   * The default scope to be used on authentication requests.
   *
   * This defaults to `profile email` if not set. If you are setting extra scopes and require
   * `profile` and `email` to be included then you must include them in the provided scope.
   *
   * Note: The `openid` scope is **always applied** regardless of this setting.
   */
  scope?: string;

  /**
   * The default audience to be used for requesting API access.
   */
  audience?: string;

  /**
   * The name of the connection configured for your application.
   * If null, it will redirect to the Auth0 Login Page and show
   * the Login Widget.
   */
  connection?: string;

  /**
   * The organization to log in to.
   *
   * This will specify an `organization` parameter in your user's login request.
   *
   * - If you provide an Organization ID (a string with the prefix `org_`), it will be validated against the `org_id` claim of your user's ID Token. The validation is case-sensitive.
   * - If you provide an Organization Name (a string *without* the prefix `org_`), it will be validated against the `org_name` claim of your user's ID Token. The validation is case-insensitive.
   *   To use an Organization Name you must have "Allow Organization Names in Authentication API" switched on in your Auth0 settings dashboard.
   *   More information is available on the [Auth0 documentation portal](https://auth0.com/docs/manage-users/organizations/configure-organizations/use-org-name-authentication-api)
   *
   */
  organization?: string;

  /**
   * The Id of an invitation to accept. This is available from the user invitation URL that is given when participating in a user invitation flow.
   */
  invitation?: string;

  /**
   * The default URL where Auth0 will redirect your browser to with
   * the authentication result. It must be whitelisted in
   * the "Allowed Callback URLs" field in your Auth0 Application's
   * settings. If not provided here, it should be provided in the other
   * methods that provide authentication.
   */
  redirect_uri?: string;

  /**
   * If you need to send custom parameters to the Authorization Server,
   * make sure to use the original parameter name.
   */
  [key: string]: any;
}

interface BaseLoginOptions {
  /**
   * URL parameters that will be sent back to the Authorization Server. This can be known parameters
   * defined by Auth0 or custom parameters that you define.
   */
  authorizationParams?: AuthorizationParams;
}

export interface Auth0ClientOptions extends BaseLoginOptions {
  /**
   * Your Auth0 account domain such as `'example.auth0.com'`,
   * `'example.eu.auth0.com'` or , `'example.mycompany.com'`
   * (when using [custom domains](https://auth0.com/docs/custom-domains))
   */
  domain: string;
  /**
   * The issuer to be used for validation of JWTs, optionally defaults to the domain above
   */
  issuer?: string;
  /**
   * The Client ID found on your Application settings page
   */
  clientId: string;
  /**
   * The value in seconds used to account for clock skew in JWT expirations.
   * Typically, this value is no more than a minute or two at maximum.
   * Defaults to 60s.
   */
  leeway?: number;

  /**
   * The location to use when storing cache data. Valid values are `memory` or `localstorage`.
   * The default setting is `memory`.
   *
   * Read more about [changing storage options in the Auth0 docs](https://auth0.com/docs/libraries/auth0-single-page-app-sdk#change-storage-options)
   */
  cacheLocation?: CacheLocation;

  /**
   * Specify a custom cache implementation to use for token storage and retrieval. This setting takes precedence over `cacheLocation` if they are both specified.
   */
  cache?: ICache;

  /**
   * If true, refresh tokens are used to fetch new access tokens from the Auth0 server. If false, the legacy technique of using a hidden iframe and the `authorization_code` grant with `prompt=none` is used.
   * The default setting is `false`.
   *
   * **Note**: Use of refresh tokens must be enabled by an administrator on your Auth0 client application.
   */
  useRefreshTokens?: boolean;

  /**
   * If true, fallback to the technique of using a hidden iframe and the `authorization_code` grant with `prompt=none` when unable to use refresh tokens. If false, the iframe fallback is not used and
   * errors relating to a failed `refresh_token` grant should be handled appropriately. The default setting is `false`.
   *
   * **Note**: There might be situations where doing silent auth with a Web Message response from an iframe is not possible,
   * like when you're serving your application from the file system or a custom protocol (like in a Desktop or Native app).
   * In situations like this you can disable the iframe fallback and handle the failed `refresh_token` grant and prompt the user to login interactively with `loginWithRedirect` or `loginWithPopup`."
   *
   * E.g. Using the `file:` protocol in an Electron application does not support that legacy technique.
   *
   * @example
   * let token: string;
   * try {
   *   token = await auth0.getTokenSilently();
   * } catch (e) {
   *   if (e.error === 'missing_refresh_token' || e.error === 'invalid_grant') {
   *     auth0.loginWithRedirect();
   *   }
   * }
   */
  useRefreshTokensFallback?: boolean;

  /**
   * A maximum number of seconds to wait before declaring background calls to /authorize as failed for timeout
   * Defaults to 60s.
   */
  authorizeTimeoutInSeconds?: number;

  /**
   * Specify the timeout for HTTP calls using `fetch`. The default is 10 seconds.
   */
  httpTimeoutInSeconds?: number;

  /**
   * Internal property to send information about the client to the authorization server.
   * @internal
   */
  auth0Client?: {
    name: string;
    version: string;
    env?: { [key: string]: string };
  };

  /**
   * Sets an additional cookie with no SameSite attribute to support legacy browsers
   * that are not compatible with the latest SameSite changes.
   * This will log a warning on modern browsers, you can disable the warning by setting
   * this to false but be aware that some older useragents will not work,
   * See https://www.chromium.org/updates/same-site/incompatible-clients
   * Defaults to true
   */
  legacySameSiteCookie?: boolean;

  /**
   * If `true`, the SDK will use a cookie when storing information about the auth transaction while
   * the user is going through the authentication flow on the authorization server.
   *
   * The default is `false`, in which case the SDK will use session storage.
   *
   * @notes
   *
   * You might want to enable this if you rely on your users being able to authenticate using flows that
   * may end up spanning across multiple tabs (e.g. magic links) or you cannot otherwise rely on session storage being available.
   */
  useCookiesForTransactions?: boolean;

  /**
   * Number of days until the cookie `auth0.is.authenticated` will expire
   * Defaults to 1.
   */
  sessionCheckExpiryDays?: number;

  /**
   * The domain the cookie is accessible from. If not set, the cookie is scoped to
   * the current domain, including the subdomain.
   *
   * Note: setting this incorrectly may cause silent authentication to stop working
   * on page load.
   *
   *
   * To keep a user logged in across multiple subdomains set this to your
   * top-level domain and prefixed with a `.` (eg: `.example.com`).
   */
  cookieDomain?: string;

  /**
   * If true, data to the token endpoint is transmitted as x-www-form-urlencoded data, if false it will be transmitted as JSON. The default setting is `true`.
   *
   * **Note:** Setting this to `false` may affect you if you use Auth0 Rules and are sending custom, non-primitive data. If you disable this,
   * please verify that your Auth0 Rules continue to work as intended.
   */
  useFormData?: boolean;

  /**
   * Modify the value used as the current time during the token validation.
   *
   * **Note**: Using this improperly can potentially compromise the token validation.
   */
  nowProvider?: () => Promise<number> | number;

  /**
   * If provided, the SDK will load the token worker from this URL instead of the integrated `blob`. An example of when this is useful is if you have strict
   * Content-Security-Policy (CSP) and wish to avoid needing to set `worker-src: blob:`. We recommend either serving the worker, which you can find in the module 
   * at `<module_path>/dist/auth0-spa-js.worker.production.js`, from the same host as your application or using the Auth0 CDN 
   * `https://cdn.auth0.com/js/auth0-spa-js/<version>/auth0-spa-js.worker.production.js`.
   * 
   * **Note**: The worker is only used when `useRefreshTokens: true`, `cacheLocation: 'memory'`, and the `cache` is not custom.
   */
  workerUrl?: string;
}

/**
 * The possible locations where tokens can be stored
 */
export type CacheLocation = 'memory' | 'localstorage';

/**
 * @ignore
 */
export interface AuthorizeOptions extends AuthorizationParams {
  response_type: string;
  response_mode: string;
  redirect_uri?: string;
  nonce: string;
  state: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
}

export interface RedirectLoginOptions<TAppState = any>
  extends BaseLoginOptions {
  /**
   * Used to store state before doing the redirect
   */
  appState?: TAppState;
  /**
   * Used to add to the URL fragment before redirecting
   */
  fragment?: string;
  /**
   * Used to control the redirect and not rely on the SDK to do the actual redirect.
   *
   * @example
   * const client = new Auth0Client({
   *   async onRedirect(url) {
   *     window.location.replace(url);
   *   }
   * });
   * @deprecated since v2.0.1, use `openUrl` instead.
   */
  onRedirect?: (url: string) => Promise<void>;

  /**
   * Used to control the redirect and not rely on the SDK to do the actual redirect.
   *
   * @example
   * const client = new Auth0Client({
   *   openUrl(url) {
   *     window.location.replace(url);
   *   }
   * });
   *
   * @example
   * import { Browser } from '@capacitor/browser';
   *
   * const client = new Auth0Client({
   *   async openUrl(url) {
   *     await Browser.open({ url });
   *   }
   * });
   */
  openUrl?: (url: string) => Promise<void> | void;
}

export interface RedirectLoginResult<TAppState = any> {
  /**
   * State stored when the redirect request was made
   */
  appState?: TAppState;
}

export interface PopupLoginOptions extends BaseLoginOptions {}

export interface PopupConfigOptions {
  /**
   * The number of seconds to wait for a popup response before
   * throwing a timeout error. Defaults to 60s
   */
  timeoutInSeconds?: number;

  /**
   * Accepts an already-created popup window to use. If not specified, the SDK
   * will create its own. This may be useful for platforms like iOS that have
   * security restrictions around when popups can be invoked (e.g. from a user click event)
   */
  popup?: any;
}

export interface GetTokenSilentlyOptions {
  /**
   * When `off`, ignores the cache and always sends a
   * request to Auth0.
   * When `cache-only`, only reads from the cache and never sends a request to Auth0.
   * Defaults to `on`, where it both reads from the cache and sends a request to Auth0 as needed.
   */
  cacheMode?: 'on' | 'off' | 'cache-only';

  /**
   * Parameters that will be sent back to Auth0 as part of a request.
   */
  authorizationParams?: {
    /**
     * There's no actual redirect when getting a token silently,
     * but, according to the spec, a `redirect_uri` param is required.
     * Auth0 uses this parameter to validate that the current `origin`
     * matches the `redirect_uri` `origin` when sending the response.
     * It must be whitelisted in the "Allowed Web Origins" in your
     * Auth0 Application's settings.
     */
    redirect_uri?: string;

    /**
     * The scope that was used in the authentication request
     */
    scope?: string;

    /**
     * The audience that was used in the authentication request
     */
    audience?: string;

    /**
     * If you need to send custom parameters to the Authorization Server,
     * make sure to use the original parameter name.
     */
    [key: string]: any;
  };

  /** A maximum number of seconds to wait before declaring the background /authorize call as failed for timeout
   * Defaults to 60s.
   */
  timeoutInSeconds?: number;

  /**
   * If true, the full response from the /oauth/token endpoint (or the cache, if the cache was used) is returned
   * (minus `refresh_token` if one was issued). Otherwise, just the access token is returned.
   *
   * The default is `false`.
   */
  detailedResponse?: boolean;
}

export interface GetTokenWithPopupOptions extends PopupLoginOptions {
  /**
   * When `off`, ignores the cache and always sends a request to Auth0.
   * When `cache-only`, only reads from the cache and never sends a request to Auth0.
   * Defaults to `on`, where it both reads from the cache and sends a request to Auth0 as needed.
   */
  cacheMode?: 'on' | 'off' | 'cache-only';
}

export interface LogoutUrlOptions {
  /**
   * The `clientId` of your application.
   *
   * If this property is not set, then the `clientId` that was used during initialization of the SDK is sent to the logout endpoint.
   *
   * If this property is set to `null`, then no client ID value is sent to the logout endpoint.
   *
   * [Read more about how redirecting after logout works](https://auth0.com/docs/logout/guides/redirect-users-after-logout)
   */
  clientId?: string | null;

  /**
   * Parameters to pass to the logout endpoint. This can be known parameters defined by Auth0 or custom parameters
   * you wish to provide.
   */
  logoutParams?: {
    /**
     * When supported by the upstream identity provider,
     * forces the user to logout of their identity provider
     * and from Auth0.
     * [Read more about how federated logout works at Auth0](https://auth0.com/docs/logout/guides/logout-idps)
     */
    federated?: boolean;
    /**
     * The URL where Auth0 will redirect your browser to after the logout.
     *
     * **Note**: If the `client_id` parameter is included, the
     * `returnTo` URL that is provided must be listed in the
     * Application's "Allowed Logout URLs" in the Auth0 dashboard.
     * However, if the `client_id` parameter is not included, the
     * `returnTo` URL must be listed in the "Allowed Logout URLs" at
     * the account level in the Auth0 dashboard.
     *
     * [Read more about how redirecting after logout works](https://auth0.com/docs/logout/guides/redirect-users-after-logout)
     */
    returnTo?: string;

    /**
     * If you need to send custom parameters to the logout endpoint, make sure to use the original parameter name.
     */
    [key: string]: any;
  };
}

export interface LogoutOptions extends LogoutUrlOptions {
  /**
   * Used to control the redirect and not rely on the SDK to do the actual redirect.
   *
   * @example
   * await auth0.logout({
   *   async onRedirect(url) {
   *     window.location.replace(url);
   *   }
   * });
   * @deprecated since v2.0.1, use `openUrl` instead.
   */
  onRedirect?: (url: string) => Promise<void>;

  /**
   * Used to control the redirect and not rely on the SDK to do the actual redirect.
   *
   * Set to `false` to disable the redirect, or provide a function to handle the actual redirect yourself.
   *
   * @example
   * await auth0.logout({
   *   openUrl(url) {
   *     window.location.replace(url);
   *   }
   * });
   *
   * @example
   * import { Browser } from '@capacitor/browser';
   *
   * await auth0.logout({
   *   async openUrl(url) {
   *     await Browser.open({ url });
   *   }
   * });
   */
  openUrl?: false | ((url: string) => Promise<void> | void);
}

/**
 * @ignore
 */
export interface AuthenticationResult {
  state: string;
  code?: string;
  error?: string;
  error_description?: string;
}

/**
 * @ignore
 */
export interface TokenEndpointOptions {
  baseUrl: string;
  client_id: string;
  grant_type: string;
  timeout?: number;
  auth0Client: any;
  useFormData?: boolean;
  [key: string]: any;
}

export type TokenEndpointResponse = {
  id_token: string;
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  scope?: string;
};

/**
 * @ignore
 */
export interface OAuthTokenOptions extends TokenEndpointOptions {
  code_verifier: string;
  code: string;
  redirect_uri: string;
  audience: string;
  scope: string;
}

/**
 * @ignore
 */
export interface RefreshTokenOptions extends TokenEndpointOptions {
  refresh_token: string;
}

/**
 * @ignore
 */
export interface JWTVerifyOptions {
  iss: string;
  aud: string;
  id_token: string;
  nonce?: string;
  leeway?: number;
  max_age?: number;
  organization?: string;
  now?: number;
}

export interface IdToken {
  __raw: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: string;
  updated_at?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  azp?: string;
  nonce?: string;
  auth_time?: string;
  at_hash?: string;
  c_hash?: string;
  acr?: string;
  amr?: string[];
  sub_jwk?: string;
  cnf?: string;
  sid?: string;
  org_id?: string;
  org_name?: string;
  [key: string]: any;
}

export class User {
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: string;
  updated_at?: string;
  sub?: string;
  [key: string]: any;
}

/**
 * @ignore
 */
export type FetchOptions = {
  method?: string;
  headers?: Record<string, string>;
  credentials?: 'include' | 'omit';
  body?: string;
  signal?: AbortSignal;
};

export type GetTokenSilentlyVerboseResponse = Omit<
  TokenEndpointResponse,
  'refresh_token'
>;

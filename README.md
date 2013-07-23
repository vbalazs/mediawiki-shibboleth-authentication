### `LocalSettings.php` configuration example

~~~PHP
require_once('extensions/ShibAuthPlugin.php');

//Allow for empty paswords
$wgMinimalPasswordLength = 0;

// Last portion of the shibboleth WAYF url for lazy sessions.
// This value is found in your shibboleth.xml file on the setup for your SP
// WAYF url will look something like: /Shibboleth.sso/WAYF/$shib_WAYF
$shib_WAYF = "Login";

//Are you using an old style WAYF (Shib 1.3) or new style Discover Service (Shib 2.x)?
//Values are WAYF or DS, defaults to WAYF
$shib_WAYFStyle = "DS";

// Default for compatibility with previous version: false
$shib_Https = true;

// Prompt for user to login
$shib_LoginHint = "Login with SSO";

// Prompt for user to log out
$shib_LogoutHint = "Logout";

// Where is the assertion consumer service located on the website?
// Default: "/Shibboleth.sso"
$shib_AssertionConsumerServiceURL = "";

// Map Real Name to what Shibboleth variable(s)?
$shib_RN = isset($_SERVER['HTTP_COMMON_NAME']) ? $_SERVER['HTTP_COMMON_NAME'] : null;

// Map e-mail to what Shibboleth variable?
$shib_email = isset($_SERVER['HTTP_EMAIL']) ? $_SERVER['HTTP_EMAIL'] : null;

// The ShibUpdateUser hook is executed on login.
// It has two arguments:
// - $existing: True if this is an existing user, false if it is a new user being added
// - &$user: A reference to the user object. 
//           $user->updateUser() is called after the function finishes.
// In the event handler you can change the user object, for instance set the email address or the real name
// The example function shown here should match behavior from previous versions of the extension:

$wgHooks['ShibUpdateUser'][] = 'ShibUpdateTheUser';

function ShibUpdateTheUser($existing, &$user) {
        global $shib_email;
        global $shib_RN;
        if (! $existing) {
                if($shib_email != null)
                        $user->setEmail($shib_email);
                if($shib_RN != null)
                        $user->setRealName($shib_RN);
        }
        return true;
}
// This is required to map to something
// You should beware of possible namespace collisions, it is best to chose
// something that will not violate MW's usual restrictions on characters
// Map Username to what Shibboleth variable?
$shib_UN = isset($_SERVER['HTTP_UID']) ? $_SERVER['HTTP_UID'] : null;

# hide "IP login" and default login link
$wgShowIPinHeader = false;
function NoLoginLinkOnMainPage( &$personal_urls ){
    unset( $personal_urls['login'] );
    unset( $personal_urls['anonlogin'] );
    return true;
}
$wgHooks['PersonalUrls'][]='NoLoginLinkOnMainPage';

# to disable factory user login
function disableUserLoginSpecialPage(&$list) {
        unset($list['Userlogin']);
        return true;
}
$wgHooks['SpecialPage_initList'][]='disableUserLoginSpecialPage';

// Activate Shibboleth Plugin
SetupShibAuth();
~~~

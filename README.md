# Python-Brute-Force-detection-tool-with-IP-address-reputation
For this to work you NEED a API key for abuseipdb.com. You can put in the cron tab to execute as often as you would like, i recomend making a copy of auth.log or any other log file that you use and clear it every 24 hours. Free API key has limited API calls a day so using the script once can use all of them.

The script check auth.log(by default), finds failed connections saves them, and counts how many times this IP address tried to connect and to which users. Then uses the API to check how malicious is the IP address and saves the results.

The implementation is very convoluted and can be done in a much simpler and more efficient way, just replacing the dictionary would improve the project and make sorting much simpler.

Arguments when launching:

--all - will check for both telnet and SSH

--ssh - will only check ssh

--telnet - will only check telnet

--save - optional, define where results will be saved

Cron tab entry can look like this:

0 * * * 1 /tmp/script.py


There is also an example auth.log file provided, USE IT WITH --ssh ARGUMENT! ALSO WATCH OUT YOU CAN REACH THE API CALL LIMIT FOR ONE DAY VERY QUICKLY IF YOU USE THE EXAMPLE FILE TOO OFTEN

If all IP addresses have confidence level of 0, everything is fine this means none of these IPs are malicious.

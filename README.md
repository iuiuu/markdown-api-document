# AA公司BC平台接口文档 v3.2.0


## 1 规范说明

### 1.1 通信协议

HTTPS协议

### 1.2 请求方法
所有接口只支持POST方法发起请求。

### 1.3 字符编码
HTTP通讯及报文BASE64编码均采用UTF-8字符集编码格式。

### 1.4 格式说明
元素出现要求说明：

符号				|说明
:----:			|:---
R				|报文中该元素必须出现（Required）
O				|报文中该元素可选出现（Optional）
C				|报文中该元素在一定条件下出现（Conditional）

### 1.5 报文规范说明

1. 报文规范仅针对交易请求数据进行描述；  

2. 报文规范中请求报文的内容为Https请求报文中RequestData值的明文内容；

3. 报文规范分为请求报文和响应报文。请求报文描述由发起方，响应报文由报文接收方响应。

### 1.6 请求报文结构
接口只接收两个参数 **RequestData** 和 **SignData** ，其中RequestData的值为请求内容，SignData的值为签名内容。

#### 1.6.1 参数说明
**RequestData（请求内容）：** 其明文为每次请求的具体参数，采用 JSON 格式，依次经过 DES 加密（以UTF-8编码、BASE64编码输出结果）和 URLEncode 后，作为 RequestData 的值。  

**SignData（签名内容）：** 请求参数（明文）的MD5加密字符串，用于校验RequestData是否合法。

#### 1.6.2 请求内容（RequestData）明文结构说明

采用JSON格式，其中包含Header（公有参数）、Body（私有参数）节点：

名称		|描述											|备注
:--		|:--											|:--
公共参数	|每个接口都包含的通用参数，以JSON格式存放在Header属性	|详见以下公共参数说明
私有参数	|每个接口特有的参数，以JSON格式存放在Body属性		|详见每个接口定义

**公共参数说明：**

公共参数（Header）是用于标识产品及接口鉴权的参数，每次请求均需要携带这些参数：

参数名称				|类型		|出现要求	|描述  
:----				|:---		|:------	|:---	
Token				|string		|R			|用户登录后token，没有登录则为空字符串
Version				|string		|R			|接口版本号
SystemId			|int		|R			|机构号，请求的系统Id
Timestamp			|long		|R			|当前UNIX时间戳


#### 1.6.3 校验流程：
服务端接收到请求后首先对RequestData进行DES解密出JSON字符串，然后对JSON字符串进行MD5加密，加密后的值与请求中的SignData值进行对比，如对比通过，视为合法请求，否则视为非法请求。

**DES加密/解密函数示例：**

C#版：

```
/// <summary>
/// 进行DES加密。
/// </summary>
/// <param name="decryptString">要加密的字符串。</param>
/// <param name="secretKey">密钥，且必须为8位。</param>
/// <returns>以Base64格式返回的加密字符串。</returns>
public static string DesEncrypt(string decryptString, string secretKey)
{
    using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
    {
        byte[] inputByteArray = Encoding.UTF8.GetBytes(decryptString);
        des.Key = Encoding.ASCII.GetBytes(secretKey);
        des.IV = Encoding.ASCII.GetBytes(secretKey);
        MemoryStream ms = new MemoryStream();
        using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
        {
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            cs.Close();
        }
        string str = Convert.ToBase64String(ms.ToArray());
        ms.Close();
        return str;
    }
}

/// <summary>
/// 进行DES解密。
/// </summary>
/// <param name="encryptedString">要解密的以Base64</param>
/// <param name="secretKey">密钥，且必须为8位。</param>
/// <returns>已解密的字符串。</returns>
public static string DesDecrypt(string encryptedString, string secretKey)
{
    byte[] inputByteArray = Convert.FromBase64String(encryptedString);
    using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
    {
        des.Key = Encoding.ASCII.GetBytes(secretKey);
        des.IV = Encoding.ASCII.GetBytes(secretKey);
        MemoryStream ms = new MemoryStream();
        using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
        {
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            cs.Close();
        }
        string str = Encoding.UTF8.GetString(ms.ToArray());
        ms.Close();
        return str;
    }
}
```

JAVA版：

```
/* DES解密 */
public static String decrypt(String message, String key) throws Exception {

    byte[] bytesrc = Base64.decode(message);
    //convertHexString(message);
    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    DESKeySpec desKeySpec = new DESKeySpec(key.getBytes("UTF-8"));
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
    SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
    IvParameterSpec iv = new IvParameterSpec(key.getBytes("UTF-8"));
    cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
    byte[] retByte = cipher.doFinal(bytesrc);
    return new String(retByte);
}


/* DES加密 */
public static byte[] encrypt(String message, String key) throws Exception {
    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    DESKeySpec desKeySpec = new DESKeySpec(key.getBytes("UTF-8"));
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
    SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
    IvParameterSpec iv = new IvParameterSpec(key.getBytes("UTF-8"));
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
    return cipher.doFinal(message.getBytes("UTF-8"));
}
```

#### 1.6.4 DES密钥

测试环境：az2ih1uY

生产环境：另外提供。

#### 1.6.5 请求报文示例
请求内容明文：

```
{
    "Header":{
        "Token":"2366CF921FAD44CCBB07FF9CD02FC90E",
        "Version":"3.2.0",
        "SystemId":100,
        "Timestamp":1502870664
    },
    "Body":{
        "Mobile":"18520322032",
        "Password":"acb000000"
    }
}

```

请求报文示例：

```
url?RequestData=UFAYIRF21XzGoaAaEU54qoDBYaFkT2KbRpWxKZuqqltApdIneF7AjlEArPLsg3%2Fo1Pu7FHFmsKZn%0A9KJb%2BGuwx0P%2F3jzv2TgwUpVtgwEdfd0vIRfqEF4jCouldaxxVBjbHvd%2F08pUoYJDNZJLvNrJ%2BsK4%0A79de92T0Cyu4hKNMUPtVI7Tp0IC%2BBw%3D%3D&SignData=0865c7d625f90d3bb5457f5d9ac3725d
```

### 1.7 响应报文结构
#### 1.7.1 结构说明
所有接口响应均采用JSON格式，如无特殊说明，每次请求的返回值中，都包含下列字段：

参数名称						|类型		|出现要求	|描述  
:----						|:---		|:------	|:---	
Code						|int		|R			|响应码，代码定义请见“附录A 响应吗说明”
Msg							|string		|R			|响应描述
Data						|object		|R			|每个接口特有的参数，详见每个接口定义


#### 1.7.2 响应报文示例

```
{
    "Code":200,
    "Msg":"调用成功",
    "Data":{
        "Channel":"A10086",
        "Type":7004
    }
}
```


## 2. 接口定义

### 2.1 密码登录
- **接口说明：** 密码登录
- **接口地址：** /account/signin

#### 2.1.1 请求参数
  
参数名称						|类型		|出现要求	|描述  
:----						|:---		|:------	|:---	
Header						|&nbsp;		|R			|请求报文头
&emsp;Token					|string		|R			|用户登录后token，没有登录则为空字符串
&emsp;Version				|string		|R			|接口版本号
&emsp;SystemId				|int		|R			|机构号，请求的系统Id
&emsp;Timestamp				|long		|R			|当前UNIX时间戳
Body						|&nbsp;		|R			|&nbsp;
&emsp;Mobile				|string		|R			|手机号
&emsp;Password				|string		|R			|密码


请求示例：

```
{
    "Header":{
        "Token":"",
        "Version":"3.2.0",
        "SystemId":100,
        "Timestamp":1502870664
    },
    "Body":{
        "Mobile":"18520322032",
        "Password":"acb000000"
    }
}

```


#### 2.1.2 返回结果

参数名称						|类型		|出现要求	|描述  
:----						|:---		|:------	|:---	
Code						|int		|R			|响应码，代码定义请见“附录A 响应吗说明”
Msg							|string		|R			|&nbsp;
Data						|object		|R			|&nbsp;
&emsp;UserId				|string		|R			|用户Id

示例：

```
{
    "Code":200,
    "Msg":"登录成功",
    "Data":{
        "UserId":"7D916C7283434955A235C17DD9B71C64"
    }
}
```



### 2.2 获取登录用户信息
- **接口说明：** 获取登录用户信息
- **接口地址：** /account/profile

#### 2.1.1 请求参数
  
参数名称						|类型		|出现要求	|描述  
:----						|:---		|:------	|:---	
Header						|&nbsp;		|R			|请求报文头
&emsp;Token					|string		|R			|用户登录后token，没有登录则为空字符串
&emsp;Version				|string		|R			|接口版本号
&emsp;SystemId				|int		|R			|机构号，请求的系统Id
&emsp;Timestamp				|long		|R			|当前UNIX时间戳
Body						|&nbsp;		|R			|&nbsp;



请求示例：

```

{
    "Header":{
        "Token":"CA64A439E7C344B0BA7F5C825E17C7AB",
        "Version":"3.2.0",
        "SystemId":100,
        "Timestamp":1502870664
    },
    "Body":null
}

```


#### 2.1.2 返回结果

参数名称						|类型		|出现要求	|描述  
:----						|:---		|:------	|:---	
Code						|int		|R			|响应码，代码定义请见“附录A 响应吗说明”
Msg							|string		|R			|&nbsp;
Data						|object		|R			|&nbsp;
&emsp;UserId				|string		|R			|用户Id
&emsp;RealName				|string		|R			|姓名
&emsp;ImageUrl				|string		|R			|头像
&emsp;Score					|int		|R			|积分
&emsp;Nickname				|string		|R			|昵称
&emsp;Sex					|int		|R			|性别：0-未知、1-男、2-女
&emsp;Title					|string		|R			|头衔


示例：

```
{
    "Code":200,
    "Msg":"处理成功",
    "Data":{
        "UserId":"7D916C7283434955A235C17DD9B71C64",
        "RealName":"张三",
        "ImageUrl":"https://img.xx.net/afdicew8751.png",
        "Score":4732,
        "Nickname":"张冠李戴",
        "Sex":1,
        "Title":"侠客Lv4"
    }
}
```


## 3 附录A 响应码说明

响应码	|说明  
:----	|:---
200		|处理成功
301		|解析报文错误
302		|无效调用凭证
303		|参数不正确
500		|系统内部错误
999		|处理失败


## 4 附录B 币种

币种		|说明  
:----	|:---
RMB		|人民币
HKD		|港币
JPY		|日元
TWD		|新台币
USD		|美元
VND		|越南盾
THB		|泰铢

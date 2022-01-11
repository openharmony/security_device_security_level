凭据为4段BASE64编码的字符串，中间用"."链接，示例如下：

`<base64-head>`.`<base64-payload>`.`<base64-signature>`.`<base64-attestation>`


构造方案如下：

##### 1.  构造header

当前header为固定json字符串，如下

 ``` json
 {
     "typ": "DSL",
 }
 ```

将header进行BASE64编码，得到`<base64-head>`：

`ewogICAgInR5cCI6ICJEU0wiLAp9`

##### 2.  构造payload

根据设备实际情况构造payload的json字符串，示例如下：
``` json
{
	"version":"1.0",
	"type":"release",
	"signTime":"20210831214343",
	"udid":"0070976B63B834FC65E7BBE648155C6D9DD..",
	"manufacture":"OHOS",
	"model":"NOH-AL00",
	"brand":"PHONE",
	"securityLevel":"SL1",
	"softwareVersion":"2.0.0.165"
}
```
将payload进行BASE64编码，得到`<base64-payload>`：

`ewkJCQkJCQoJInZlcnNpb24iOiIxLjAiLAkJCQkKCSJ0eXBlIjoicmVsZWFzZSIsCQkKCSJzaWduVEltZSI6IjIwMjEwODMxMjE0MzQzIiwKCSJ1ZGlkIjoiMDA3MDk3NkI2M0I4MzRGQzY1RTdCQkU2NDgxNTVDNkQ5REQuLiIsCgkibWFudWZhY3R1cmUiOiJIVUFXRUkiLAoJIm1vZGVsIjoiTk9ILUFMMDAiLAoJImJyYW5kIjoiSFVBV0VJIiwKCSJzZWN1cml0eUxldmVsIjoiU0wxIiwKCSJzb2Z0d2FyZVZlcnNpb24iOiIyLjAuMC4xNjUiCn0=`

##### 3. 构造signature

###### 3.1 构建待签名的原始数据

将BASE64编码后的header和payload合并，中间用符号"."连接，得到`<base64-head>`.`<base64-payload>`

示例如下：

`ewogICAgInR5cCI6ICJEU0wiLAp9`.`ewkJCQkJCQoJInZlcnNpb24iOiIxLjAiLAkJCQkKCSJ0eXBlIjoicmVsZWFzZSIsCQkKCSJzaWduVEltZSI6IjIwMjEwODMxMjE0MzQzIiwKCSJ1ZGlkIjoiMDA3MDk3NkI2M0I4MzRGQzY1RTdCQkU2NDgxNTVDNkQ5REQuLiIsCgkibWFudWZhY3R1cmUiOiJIVUFXRUkiLAoJIm1vZGVsIjoiTk9ILUFMMDAiLAoJImJyYW5kIjoiSFVBV0VJIiwKCSJzZWN1cml0eUxldmVsIjoiU0wxIiwKCSJzb2Z0d2FyZVZlcnNpb24iOiIyLjAuMC4xNjUiCn0=`

###### 3.2 生成签名私钥

**本流程需要在安全可靠的环境中执行，以确保用于签名的密钥不被泄露**

使用ECC签名算法对原始数据进行签名，生成签名用ECDSA密钥对：`<ecc-l3-pk>`和`<ecc-l3-sk>`

###### 3.3 对原始数据进行签名

将`<base64-head>`.`<base64-payload>`作为参数，使用刚刚生成的ECC私钥`<ecc-l3-sk>`对其进行签名，并对签名结果进行BASE64编码，得到返回值`<base64-signature>`

示例如下：

`e+PKCRQB1RDzOZz9hipnxe32lgufLRTDml1mt3vLNvmS3hgRgstK86ucRjJXIOfdJYi459hg82be61i6p3DkWg==`

##### 4. 构造attestation info

**本流程需要在安全可靠的环境中执行，以确保用于签名的密钥不被泄露**

**attestation info涉及到的各密钥对不需要每次都重复生成，在确保密钥安全的前提下，后续可以直接复用。**

###### 4.1 生成三级签名验证信息

1. 首先生成二级签名用ECDSA密钥对：`<ecc-l2-pk>`和`<ecc-l2-sk>`

2. 使用`<ecc-l2-sk>` 对3.2章节生成的`<ecc-l3-pk>`进行签名，得到`<ecc-l3-pk-signature>`

3. 将`<ecc-l3-pk>`和`<ecc-l3-pk-signature>`组合成json字符串示例如下：

     ``` json
{
		"userPublicKey": "<ecc-l3-pk>",
		"signature": "<ecc-l3-pk-signature>"
}
	```

###### 4.2 生成二级签名验证信息

1. 生成一级签名用ECDSA密钥对：`<ecc-root-pk>`和`<ecc-root-sk>`
2. 使用`<ecc-root-sk>` 对4.1章节生成的`<ecc-l2-pk>`进行签名，得到`<ecc-l2-pk-signature>`
3. 将`<ecc-l3-pk>`和`<ecc-l3-pk-signature>`组合成json字符串示例如下：
     ``` json
{
		"userPublicKey": "<ecc-l2-pk>",
		"signature": "<ecc-l2-pk-signature>"
}
	```

###### 4.3 生成根签名验证信息

1. 使用`<ecc-root-sk>` 对4.2章节生成的`<ecc-root-pk>`进行签名（即自签名），得到`<ecc-root-pk-self-signature>`
2. 将`<ecc-root-pk>`和`<ecc-root-pk-self-signature>`组合成json字符串示例如下：
     ``` json
{
		"userPublicKey": "<ecc-root-pk>",
		"signature": "<ecc-root-pk-self-signature>"
}
	```
###### 4.4 生成合并上述的签名验证信息
1. 将上述三组签名信息合并到一个json数组中:
     ```json
[
	    {
	        "userPublicKey": "<ecc-l3-pk>",
        		"signature": "<ecc-l3-pk-signature>"
         },
         {
             "userPublicKey": "<ecc-l2-pk>",
             "signature": "<ecc-l2-pk-signature>"
         },
         {
             "userPublicKey": "<ecc-root-pk>",
             "signature": "<ecc-root-pk-self-signature>"
         }
     ]
     ```
2.对该数据进行base64编码，得到`<base64-attestation>`


示例如下：
     `W3sidXNlclB1YmxpY0tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWFnOFZIMzN4OUpDOTYwSWsxejNKNmo1cnk0OVJENGt0TTBvQUZGenhiNHdOdS1OckZSbm5XbnZmR3hGTW16VFBMLWYxY1NqWGd2UV9NdU9aenVpclNnIiwiYWxnb3JpdGhtIjoiU0hBMzg0d2l0aEVDRFNBIiwic2lnbmF0dXJlIjoiTUdVQ01DakdwWEZPNlRjb2NtWFdMdHU1SXQ0LVRJNzFoNzhLdDYyYjZ6Mm9tcnNVWElHcnFsMTZXT0ExV2ZfdDdGSU1RZ0l4QVBHMlV5T2d0dk1pbi1hbVR6Wi1DN2ZyMWttVl9jODc4ckFnZVlrUGFxWWdPWWpiSGN0QnFzMkJCV05LMGsxTnJRIn0seyJ1c2VyUHVibGljS2V5IjoiTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVvM0N1Q0VMQzdTaUxhSkNCQ0RkY0NwZXRnSUdraFpMc0ZfYTBkZFUxQ1I3dzU0emppc0NYWkdfdXk2ZGtGZWZrZTNVMW9CaWw0eGk1OU5xeVpOZ1FQbEFISVVHeWtRcVl4cHg1WjBqQUJCSnlBSlVscHRxM0p1Wk5UQTdIOVVLNyIsImFsZ29yaXRobSI6IlNIQTM4NHdpdGhFQ0RTQSIsInNpZ25hdHVyZSI6Ik1HVUNNQ1ZXUWIxdXFLb1E5SUFMaWJiWUlUX1NWSENXem84akcwRG1WNGt6Q0JNQ3pRQU0xZEFaSERGWFdidGUyY0FfWXdJeEFJSXVmaXJHbnN3NlBEV0txRm1mQmQ5Y3BubEFyLXVXV0RqZ2xuenoyRmx2LXNkaVhYRnR3amo3Y1hUTF9FNmJRUSJ9LHsidXNlclB1YmxpY0tleSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFU09kcnY3eXhEaFoxWmRUdDB3QUxCMnhYc0ZsUGV2TkQ0b1lfWE44QWtFTVllWVVyTXBkX1hTQTdlTHo5eVJaa08yX3RoSEx4bUpURGZrOUJFeTlTa0xxUF9xOGZJdzBhSXNBMHI0SlN0djh4YVo0RWxVTGxPV2QxXzF4YV9fdnIiLCJhbGdvcml0aG0iOiJTSEEzODR3aXRoRUNEU0EiLCJzaWduYXR1cmUiOiJNR1FDTURmODNSNktLdm9tZnZyZVYycHhVSEpXb3RwM3BVOUdBWU5tcU1XUmVGcGp6WHpOVjc5dHNrZTBaa21JTVh3TXNBSXdXNUFiOWk4SnlObEp0WDJZcnpaYzJna3RranZ0U2JiSnYwaWhuUmdxMWNjUHBrVDJOc3F4ekJrZkRqOGhQWllzIn1d`

##### 5. 构造完整的凭据

用符号"."连接上述 `<base64-head>`.`<base64-payload>`.`<SIGNATURE>`.`<ATTESTATIONINFO>`

最终结果示例如下：

`ewogICAgInR5cCI6ICJEU0wiLAp9`.`ewkJCQkJCQoJInZlcnNpb24iOiIxLjAiLAkJCQkKCSJ0eXBlIjoicmVsZWFzZSIsCQkKCSJzaWduVEltZSI6IjIwMjEwODMxMjE0MzQzIiwKCSJ1ZGlkIjoiMDA3MDk3NkI2M0I4MzRGQzY1RTdCQkU2NDgxNTVDNkQ5REQuLiIsCgkibWFudWZhY3R1cmUiOiJIVUFXRUkiLAoJIm1vZGVsIjoiTk9ILUFMMDAiLAoJImJyYW5kIjoiSFVBV0VJIiwKCSJzZWN1cml0eUxldmVsIjoiU0wxIiwKCSJzb2Z0d2FyZVZlcnNpb24iOiIyLjAuMC4xNjUiCn0=`.`e+PKCRQB1RDzOZz9hipnxe32lgufLRTDml1mt3vLNvmS3hgRgstK86ucRjJXIOfdJYi459hg82be61i6p3DkWg==`.`W3sidXNlclB1YmxpY0tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWFnOFZIMzN4OUpDOTYwSWsxejNKNmo1cnk0OVJENGt0TTBvQUZGenhiNHdOdS1OckZSbm5XbnZmR3hGTW16VFBMLWYxY1NqWGd2UV9NdU9aenVpclNnIiwiYWxnb3JpdGhtIjoiU0hBMzg0d2l0aEVDRFNBIiwic2lnbmF0dXJlIjoiTUdVQ01DakdwWEZPNlRjb2NtWFdMdHU1SXQ0LVRJNzFoNzhLdDYyYjZ6Mm9tcnNVWElHcnFsMTZXT0ExV2ZfdDdGSU1RZ0l4QVBHMlV5T2d0dk1pbi1hbVR6Wi1DN2ZyMWttVl9jODc4ckFnZVlrUGFxWWdPWWpiSGN0QnFzMkJCV05LMGsxTnJRIn0seyJ1c2VyUHVibGljS2V5IjoiTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVvM0N1Q0VMQzdTaUxhSkNCQ0RkY0NwZXRnSUdraFpMc0ZfYTBkZFUxQ1I3dzU0emppc0NYWkdfdXk2ZGtGZWZrZTNVMW9CaWw0eGk1OU5xeVpOZ1FQbEFISVVHeWtRcVl4cHg1WjBqQUJCSnlBSlVscHRxM0p1Wk5UQTdIOVVLNyIsImFsZ29yaXRobSI6IlNIQTM4NHdpdGhFQ0RTQSIsInNpZ25hdHVyZSI6Ik1HVUNNQ1ZXUWIxdXFLb1E5SUFMaWJiWUlUX1NWSENXem84akcwRG1WNGt6Q0JNQ3pRQU0xZEFaSERGWFdidGUyY0FfWXdJeEFJSXVmaXJHbnN3NlBEV0txRm1mQmQ5Y3BubEFyLXVXV0RqZ2xuenoyRmx2LXNkaVhYRnR3amo3Y1hUTF9FNmJRUSJ9LHsidXNlclB1YmxpY0tleSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFU09kcnY3eXhEaFoxWmRUdDB3QUxCMnhYc0ZsUGV2TkQ0b1lfWE44QWtFTVllWVVyTXBkX1hTQTdlTHo5eVJaa08yX3RoSEx4bUpURGZrOUJFeTlTa0xxUF9xOGZJdzBhSXNBMHI0SlN0djh4YVo0RWxVTGxPV2QxXzF4YV9fdnIiLCJhbGdvcml0aG0iOiJTSEEzODR3aXRoRUNEU0EiLCJzaWduYXR1cmUiOiJNR1FDTURmODNSNktLdm9tZnZyZVYycHhVSEpXb3RwM3BVOUdBWU5tcU1XUmVGcGp6WHpOVjc5dHNrZTBaa21JTVh3TXNBSXdXNUFiOWk4SnlObEp0WDJZcnpaYzJna3RranZ0U2JiSnYwaWhuUmdxMWNjUHBrVDJOc3F4ekJrZkRqOGhQWllzIn1d`


<h1 align="center">All-in Fuzzer</h1>

<h3 align="center">Burp suite extension for auto fuzzing params, headers, body</h3>

This is an extension for Burp Suite that allows you to easily fuzz selected parts of a request with basic payloads using just two clicks. It helps identify anomalies in the responses and detect potential bugs

# Features
- FUZZ params
- FUZZ headers
- FUZZ cookies
- FUZZ body (json)
- FUZZ body (url)
- FUZZ selected text


# Usage
#### Choose the fuzzing option
```
Right-click on the request -> Extensions -> All-in Fuzzer -> Choose the fuzzing option
```
![image](https://github.com/danilmor/All-in-Fuzzer/assets/50376588/90959a28-ab52-4db3-bd0f-34e0fecfcaf6)

#### Look for anomalies
![image](https://github.com/danilmor/All-in-Fuzzer/assets/50376588/b104964c-0d0f-4a03-a4d3-d2953175c9b3)


# Installation

#### 1) Install Jython https://www.jython.org/download
#### 2) Add Jython to burp
```
Settings -> Extensions -> Python environment -> Set jython.jar in "Location of Jython standalone JAR file"
```
![image](https://github.com/danilmor/All-in-Fuzzer/assets/50376588/259d1bee-ae24-4dec-84b4-5334ea15435a)
#### 3) Add extension
```
Extensions -> Installed -> Add
```
![image](https://github.com/danilmor/All-in-Fuzzer/assets/50376588/e451fadd-580d-44a8-b734-5e1ba87644a1)



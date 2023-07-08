<?php
class ForgotPassword {
	public $settings = array(
		'name' => 'Forgot Password',
		'description' => 'Allows users to reset their password if they are unable to access their account.',
	);
	function user_area() {
		global $billic, $db;
		$billic->set_title('Forgot Password');
		if (!empty($billic->user)) {
			$billic->redirect('/');
		}
		$billic->check_bruteforce();
		if (!empty($_GET['secret'])) {
			if (!empty($_GET['secret'])) {
				$db->q("DELETE FROM `reset_pw` WHERE `timestamp` < ?", (time() - 1800));
				if (isset($_POST['change'])) {
					if (empty($_POST['password'])) {
						$billic->errors[] = 'Password is required';
					}
					if (empty($_POST['password2'])) {
						$billic->errors[] = 'You need to enter the password twice';
					}
					if (empty($billic->errors)) {
						if ($_POST['password'] != $_POST['password2']) {
							$billic->errors[] = 'Passwords do not match';
						}
					}
					if (empty($billic->errors)) {
						if ($_SESSION['captcha'] != $_POST['captcha']) {
							unset($_SESSION['captcha']);
							$billic->errors[] = 'Captcha code invalid, please try again';
						}
					}
					if (empty($billic->errors)) {
						$reset_pw = $db->q("SELECT * FROM `reset_pw` WHERE `secret` = ?", $_GET['secret']);
						$reset_pw = $reset_pw[0];
						if (empty($reset_pw)) {
							$billic->errors[] = 'Secret code is invalid, please try sending a new password reset request';
						}
					}
					if (empty($billic->errors)) {
						$salt = $billic->rand_str(5);
						$password = md5($salt . $_POST['password']) . ':' . $salt;
						$db->q("UPDATE `users` SET `password` = ? WHERE `id` = ?", $password, $reset_pw['userid']);
						$db->q("DELETE FROM `reset_pw` WHERE `secret` = ?", $_GET['secret']);
						unset($_SESSION['captcha']);
						$updated = true;
						$reset = true;
					}
				}
				if ($reset == true) {
					echo '<h1>Password Reset Successful</h1>';
					$billic->show_errors();
?>
					<table>
					<tr><td align="center" colspan="2">Your password has been reset. Use the form above to login.</td></tr>
					</table>
					<?php
					exit;
				}
			}
			echo '<h1>Reset Your Password</h1>';
			$billic->show_errors();
?>
			<form method="POST" name="login">
			<table>
			<tr><td align="right"><b>New Password:</b></td><td><input type="password" class="form-control" name="password" size="20" /></td></tr>
			<tr><td align="right"><b>Repeat Password:</b></td><td><input type="password" class="form-control" name="password2" size="20" /></td></tr>
			<tr><td><img src="/Captcha/<?php echo time(); ?>" width="150" height="75" alt="CAPTCHA"></td><td align="center">Enter the code you see<br><input type="text" class="form-control" name="captcha" size="6" style="text-align:center;width:250px" /></td></td></tr>
			<tr><td colspan="2" align="center"><input type="submit" class="btn btn-primary" name="change" value="Change Password &raquo;" /></td></tr>
			</table>
			</form>
			<?php
			exit;
		}
		$sent = false;
		if (isset($_POST['reset'])) {
			if (empty($_POST['email'])) {
				$billic->errors[] = 'Email is required';
			}
			if (empty($_POST['captcha'])) {
				$billic->errors[] = 'Captcha is required';
			}
			if (empty($billic->errors)) {
				if ($_SESSION['captcha'] != $_POST['captcha']) {
					unset($_SESSION['captcha']);
					$billic->errors[] = 'Captcha code invalid, please try again';
				}
			}
			if (empty($billic->errors)) {
				$user_row = $db->q("SELECT `id`, `email` FROM `users` WHERE `email` = ?", $_POST['email']);
				$user_row = $user_row[0];
				if (empty($user_row)) {
					$billic->errors[] = 'The email address is not in the system';
				}
				$billic->bruteforce(array(
					'desc' => 'Forgot Password - Invalid email',
				));
			}
			if (empty($billic->errors)) {
				$i = 0;
				while (true) {
					$i++;
					if ($i == 999) {
						fatal_error('Failed to generate secret code');
					}
					$secret = $billic->rand_str(20);
					$r = $db->q("SELECT COUNT(*) FROM `reset_pw` WHERE `secret` = ?", $secret);
					if ($r[0]['COUNT(*)'] == 0) {
						break;
					}
				}
				$db->q("DELETE FROM `reset_pw` WHERE `userid` = ?", $user_row['id']);
				$db->insert('reset_pw', array(
					'timestamp' => time() ,
					'userid' => $user_row['id'],
					'secret' => $secret,
					'ip' => $_SERVER['REMOTE_ADDR'],
				));
				$url = 'http' . (empty($_SERVER['HTTPS']) ? '' : 's') . '://' . $_SERVER['HTTP_HOST'] . '/User/ForgotPassword/secret/' . $secret . '/';
				$billic->email($user_row['email'], 'Password Reset', 'Somebody has requested to reset your password from the IP address ' . $_SERVER['REMOTE_ADDR'] . '<br><br>If you do not want to reset your password, please ignore this email.<br><br>To reset your password, click here: <a href="' . $url . '">' . $url . '</a><br>');
				unset($_SESSION['captcha']);
				$sent = true;
			}
		}
		if ($sent == true) {
			echo '<h1>Forgot Password</h1>';
			$billic->show_errors();
?>
			<table>
			<tr><td align="center" colspan="2">An email has been sent to your email address. Please click the link inside the email.</td></tr>
			</table>
			<?php
			exit;
		}
		echo '<h1>Forgot Password</h1>';
		$billic->show_errors();
?>
	<form method="POST" name="login">
	<table>
	<tr><td align="right"><b>Email Address:</b></td><td><input type="text" class="form-control" name="email" size="20" value="<?php echo @safe($_POST['email']); ?>" /></td></tr>
	<tr><td><img src="/Captcha/<?php echo time(); ?>" width="150" height="75" alt="CAPTCHA"></td><td align="center">Enter the code you see<br><input type="text" class="form-control" name="captcha" size="6" style="text-align:center;width:150px" /></td></td></tr>
	<tr><td colspan="2" align="center"><input type="submit" class="btn btn-primary" name="reset" value="Send Email &raquo;" /></td></tr>
	</table>
	</form>
	<?php
	}
}

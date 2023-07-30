document.getElementById('settings-form').addEventListener('submit', function (event) {
    event.preventDefault();

    var username = document.getElementById('username').value;
    var email = document.getElementById('email').value;
    var currentPassword = document.getElementById('current-password').value;
    var newPassword = document.getElementById('new-password').value;
    var confirmNewPassword = document.getElementById('confirm-new-password').value;


    fetch('/update_password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'username=' + encodeURIComponent(username) + 
              '&email=' + encodeURIComponent(email) + 
              '&current_password=' + encodeURIComponent(currentPassword) + 
              '&new_password=' + encodeURIComponent(newPassword) +
              '&confirm_new_password=' + encodeURIComponent(confirmNewPassword),
    })
    .then((response) => response.text())
    .then((message) => alert(message))
    .catch((error) => console.error('Error:', error));
});

window.onload = function() {
    var username = "{{ session['user'] }}";

    fetch('/get_user_data', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'username=' + encodeURIComponent(username),
    })
    .then(response => response.json())
    .then(data => {
        location.reload();
        if (data.error) {
            alert(data.error);
        } else {
            document.getElementById('username').value = data.username;
            document.getElementById('email').value = data.email;
        }
    });
};

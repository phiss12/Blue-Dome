document.addEventListener('DOMContentLoaded', function() {

    // Delete User
    Array.from(document.querySelectorAll('.delete-btn')).forEach(function(element) {
        element.addEventListener('click', function() {
            var userId = this.getAttribute('data-id');
            var parent = this.parentNode.parentNode;
            
            // Add confirmation before the deletion
            var deleteUser = confirm("Are you sure you want to delete this user?");
            if (deleteUser) {
                fetch('/delete_user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ "user_id": userId })
                }).then(function(response) {
                    location.reload();
                    return response.json();
                }).then(function(data) {
                    // On success, remove user row from the table
                    parent.remove();
                    alert(data.message);
                });
            }
        });
    });


    // Add User Modal
    var addUserBtn = document.getElementById('add-user-btn');
    var addUserModal = document.getElementById('add-user-modal');
    var addUserCloseBtn = document.getElementById('close-modal-btn');

    // When the "Add User" button is clicked, show the modal dialog
    addUserBtn.addEventListener('click', function () {
        addUserModal.style.display = 'block';
    });

    // When the close button is clicked, hide the modal dialog
    addUserCloseBtn.addEventListener('click', function () {
        addUserModal.style.display = 'none';
    });


    // Edit User Model
    var editUserBtns = document.querySelectorAll('.edit-btn');
    var editUserModal = document.getElementById('edit-user-modal');
    var editUserCloseBtn = document.getElementById('close-edit-modal-btn');

    // Edit User
    var userId;
    editUserBtns.forEach(function(editUserBtn) {
        editUserBtn.addEventListener('click', function() {
            userId = this.getAttribute('data-id');
            var row = this.parentNode.parentNode;
            var rowData = Array.from(row.querySelectorAll('td')).map(td => td.textContent);

           
            document.getElementById('edit-user-name').value = rowData[0];
            document.getElementById('edit-user-username').value = rowData[1];
            
            document.getElementById('edit-user-email').value = rowData[2];
            document.getElementById('edit-user-groups').value = rowData[3];

            editUserModal.style.display = 'block';
        });
    });
    // When the close button is clicked, hide the modal dialog
    editUserCloseBtn.addEventListener('click', function () {
        editUserModal.style.display = 'none';
     });


    // When the user clicks anywhere outside of the modal, close it
    window.addEventListener('click', function (event) {
        if (event.target === addUserModal) {
            addUserModal.style.display = 'none';
        } else if (event.target === editUserModal) {
            editUserModal.style.display = 'none';
        }
    } );
    // Submit Edit User Form
    document.getElementById('edit-user-form').addEventListener('submit', function(e) {
        e.preventDefault();

        var userData = {
            "user_id": userId,
            "name": document.getElementById('edit-user-name').value,
            "username": document.getElementById('edit-user-username').value,
           
            "email": document.getElementById('edit-user-email').value,
            "groups": document.getElementById('edit-user-groups').value
        };

        editUserModal.style.display = 'none';

        fetch('/edit_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userData)
        }).then(function(response) {
            location.reload();
            return response.json();
        }).then(function(data) {
            document.getElementById('edit-user-modal').style.display = 'none';
            alert(data.message);
        });
    });

    var addUserForm = document.getElementById('add-user-form')
    document.getElementById('add-user-form').addEventListener('submit', function(event) {
        event.preventDefault();

        // Get the form input values
        var name = document.getElementById('user-name').value;
        var username = document.getElementById('user-username').value;
        var password = document.getElementById('user-password').value;
        var email = document.getElementById('user-email').value;
        var groups = document.getElementById('user-groups').value;

        // Clear the form inputs
        addUserForm.reset();

        // Hide the modal dialog
        addUserModal.style.display = 'none';

        fetch('/add_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name: name,
                username: username,
                password: password,
                email: email,
                groups: groups
            }),
        }).then(function(response) {
            location.reload();
            return response.json();
        }).then(function(data) {
            alert(data.message);
        });
    });
    
});

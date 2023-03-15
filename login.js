const fn = (event) => {
event.preventDefault();
$(document).ready(function () {
    $("form").submit(function (event) {
        var formData = {
            name: $("#log_email").val(),
            password: $("#log_password").val(),
        };

        $.ajax({
            type: "POST",
            url: "login_handler.php",
            data: formData,
            dataType: "json",
            encode: true,
        }).done(function (data) {
            console.log(data);
        });

        
    });
});
}

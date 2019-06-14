$(function() {
        
    // Private message submit    
    $("#messageform").submit(function() {

        console.log("Sending private message...")
        // Post the form values via AJAX
        $.post('/out/privatemessage', {message: $("#private_msg").val(), dest_user:$("#target_user").val()}, function(data) {
            console.log("Sent private message")
            // Update heading with response
            data = JSON.parse(data);
            $("#test").html(data['message'] + ":" + data['user']) ;
        });
        return false ;
    });

    // Broadcast submit
    $("#broadcastform").submit(function() {

        console.log("Broadcasting...")
        // Post the form values via AJAX
        $.post('/out/broadcast', {message: $("#broadcast_msg").val()}, function(data) {
            console.log("Sent message")
            // Update heading with response
            data = JSON.parse(data);
            $("#test").html(data['message'] + ":" + data["count"]) ;
        });
        return false ;
    });

    // Ping
    // $("#ping").submit(function() {

    //     console.log("Pinging central server...")
    //     // Post the form values via AJAX
    //     $.post('/out/ping', {}, function(data) {
    //         console.log("Received response")
    //     });
    //     return false ;
    // });

    // Test update users
    // $("#updateUsers").submit(function() {

    //     console.log("Updating user list...")
    //     // Post the form values via AJAX
    //     $.post('/out/getPrivateData', {}, function(data) {
    //         if (data=="success") console.log("User list updated");
    //     });
    //     return false ;
    // });

    // Report
    $("#report").submit(function() {

        console.log("Reporting to login server...")
        // Post the form values via AJAX
        $.post('/out/report', {status:$("#status").val()}, function(data) {
            data = JSON.parse(data)
            if (data["response"]=="ok") console.log("Reported successfully");
        });
        return false ;
    });

    // Ping regularly
    (function pingCheck() {
        $.ajax({
          url: '/out/ping_check', 
          success: function(data) {
            data = JSON.parse(data);
            console.log("Pinged: " + data["userCount"]);
            console.log("Verified: " + data["successCount"]);
            console.log("Status: " + data["success"]);
          },
          complete: function() {
            // Schedule the next request when the current one's complete
            setTimeout(pingCheck, 300000);
          }
        });
      })();
    
    // Report regularly
    (function reportToLoginServer() {
        $.ajax({
          url: '/out/report', 
          success: function(data) {
            data = JSON.parse(data);
            console.log(data);
          },
          complete: function() {
            // Schedule the next request when the current one's complete
            setTimeout(reportToLoginServer, 60000); //every minute
          }
        });
      })();

    // Update active users
    (function updateUsers() {
        $.ajax({
          url: '/out/listusers', 
          success: function(data) {
            data = JSON.parse(data);
            console.log(data);
          },
          complete: function() {
            // Schedule the next request when the current one's complete
            setTimeout(updateUsers, 30000); //every half minute
          }
        });
      })();
});

function likeMessage(messageSignature){
  console.log("You liked: " + messageSignature);
}

function blockUser(user){
  console.log("You blocked: " + user);
}

function blockMessage(messageSignature){
  console.log("You blocked: " + messageSignature);
}

// Attempt to update page elements
function updatePage(){
  $.ajax({
    url:"/out/update",
    type:"get",
    success:function(data){
    },
    complete:function(data){
      setTimeout(updatePage,10000);
    }
  })
}
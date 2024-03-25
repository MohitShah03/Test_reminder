use crate::{models::task_model::Task, repository::mongodb_repo::MongoRepo};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use mongodb::options::Credential;
use mongodb::results::InsertOneResult;
use rocket::{http::Status, response::status::Custom, serde::json::Json, Request, State};
use rocket::request::{FromRequest, Outcome};
use mongodb::bson::{oid::ObjectId, Bson};
// use rocket::
use lettre::{Message, SmtpTransport, Transport, message::{Mailbox, SinglePart}};
use tokio::task;
// use tokio::task;
use std::error::Error;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// use serde::{Serialize, Deserialize};
use chrono::{DateTime, ParseError, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
// use rocket::response::status::Custom;
use serde_json::{json, Value as JsonValue};
extern crate dotenv;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use std::env;
use crate::private::JWT_SECRET;

fn parse_remider_date(date_str: &str) -> Result<DateTime<Utc>, ParseError> {
    println!("Bye: {}", date_str);
    DateTime::parse_from_rfc3339(date_str).map(|dt| dt.with_timezone(&Utc))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizedUser {
    sub: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}
pub enum DecodeJwtHelper {
    Ok(TokenData<Claims>),
    Err,
}

fn check_data_from_token(auth_header: Option<&str>) -> Result<Vec<&str>, ()> {
    return if let Some(auth_string) = auth_header {
        let vec_header = auth_string.split_whitespace().collect::<Vec<_>>();
        if vec_header.len() != 2
            && vec_header[0] == "Bearer"
            && !vec_header[0].is_empty()
            && !vec_header[1].is_empty()
        {
            Err(())
        } else {
            Ok(vec_header)
        }
    } else {
        Err(())
    };
}

fn decode_jwt(token: String, secret: &'static str) -> DecodeJwtHelper {
    dotenv().ok();
    let secret= secret;
    println!("{}",secret);
    let secret_key = secret.as_bytes();
    let token = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret_key),
        &Validation::new(Algorithm::HS256),
    );
    println!("{:?}",token);
    match token {
        Ok(token_string) => DecodeJwtHelper::Ok(token_string),
        Err(_) => DecodeJwtHelper::Err,
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizedUser {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = request.headers().get_one("Authorization");
        println!("Hiiii");
        println!("Bhai Bhai {:?}",auth_header);
        match check_data_from_token(auth_header) {
            Ok(vec_header) => match decode_jwt(vec_header[1].to_string(), JWT_SECRET) {
                DecodeJwtHelper::Ok(token_data) =>{ Outcome::Success(AuthorizedUser {
                    sub: token_data.claims.sub,
                })},
                DecodeJwtHelper::Err => Outcome::Error((Status::Unauthorized, ())),
            },
            Err(_) => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

fn send_email_notification(recipient:&str, task_name:&str)->Result<(), Box<dyn Error>>{
    let email_message = format!("Your {} task is due now", task_name);
    let sender_mailbox = Mailbox::new(None, "macshah13158@gmail.com".parse().unwrap());
    let recipient_mailbox = Mailbox::new(None, recipient.parse().unwrap());
    let email = Message::builder()
        .from(sender_mailbox)
        .to(recipient_mailbox)
        .subject("Task Reminder")
        .body(email_message)
        .unwrap();

    let credentials = Credentials::new("macshah13158@gmail.com".to_string(), "aclg tatp jazh ivtl".to_string());

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(credentials)
        .build();

 let result = mailer.send(&email);
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }

}

#[post("/addreminder", data = "<new_task>")]
pub fn add_reminder(
    db: &State<MongoRepo>,
    new_task: Json<Task>,
    auth:AuthorizedUser
) -> Result<Json<InsertOneResult>, Custom<JsonValue>> {
    let new_task_data = new_task.into_inner();
    println!("an: {}", new_task_data.task.is_empty());
    println!("Bhai : {:?}",auth.sub);

    let user_id = match ObjectId::parse_str(auth.sub){
        Ok(object_id) => Some(object_id),
        Err(_) => None,
    };
    if new_task_data.task.is_empty() {
        let json_response = json!({"error" : "Please provide a task"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }

    if new_task_data.description.is_empty() {
        let json_response = json!({"error" : "Please provide a description"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }

    // Check if the date is valid
    if let Some(reminder_date) = new_task_data.reminder_date {
        if reminder_date <= Utc::now() {
            let json_response = json!({"error": "Reminder date must be in the future"});
            return Err(Custom(Status::BadRequest, json_response.into()));
        }

        match send_email_notification(&new_task_data.user_email, &new_task_data.task) {
            Ok(_) => println!("Email was send..."),
            Err(err) => println!("There was an error while sending mail : {}",err)
        }
        // let parse_date = match parse_remider_date(&reminder_date.to_rfc3339()) {
        //     Ok(parsed_date) => parsed_date,
        //     Err(_) => {
        //         let json_response = json!({"error":"Date formate is not valid"});
        //         return Err(Custom(Status::BadRequest, json_response.into()));
        //     }
        // };
        // println!("hello: {}", parse_date);
    }

    let task_data = Task {
        id: None,
        task: new_task_data.task.to_owned(),
        description: new_task_data.description.to_owned(),
        reminder_date: new_task_data.reminder_date,
        user_id:Some(user_id.expect("REASON")),
        user_email:new_task_data.user_email.to_owned()
    };
    let task_detail = db.db_create_task(task_data);
    match task_detail {
        Ok(reminder) => Ok(Json(reminder)),
        Err(_) => {
            let json_response = json!({ "error": "Internal Server Error" });
            Err(Custom(Status::InternalServerError, json_response.into()))
        }
    }
}

#[get("/showreminder")]
pub fn get_reminder(db: &State<MongoRepo>) -> Result<Json<Vec<Task>>, Custom<JsonValue>> {
    let task_details = db.get_all_tasks();

    let task_vec = match task_details {
        Ok(tasks) => tasks,
        Err(_) => return Err(Custom(Status::NotFound, json!({ "error": "No tasks found" }).into())),
    };

    // Iterate over tasks to schedule reminders
    for task in &task_vec {
        if let Some(reminder_date) = task.reminder_date {
            let now = Utc::now();
            if reminder_date <= now {
                // Send reminder immediately or at scheduled time
                if let Err(err) = send_email_notification(&task.user_email, &task.task) {
                    println!("Failed to send reminder for task {}: {}", task.task, err);
                } else {
                    println!("Reminder sent for task {}", task.task);
                }
            } else {
                // Calculate the duration to wait before sending the reminder
                let duration_until_reminder = reminder_date.signed_duration_since(now).to_std().unwrap();
                let task_clone = task.clone(); // Clone task for closure
                thread::spawn(move || {
                    thread::sleep(duration_until_reminder);
                    if let Err(err) = send_email_notification(&task_clone.user_email, &task_clone.task) {
                        println!("Failed to send reminder for task {}: {}", task_clone.task, err);
                    } else {
                        println!("Reminder sent for task {}", task_clone.task);
                    }
                });
            }
        }
    }

    // Return the Vec<Task> as JSON
    Ok(Json(task_vec))
}


#[put("/updatereminder/<id>", data = "<new_task>")]
pub fn update_reminder(
    db: &State<MongoRepo>,
    id: String,
    auth:AuthorizedUser,
    new_task: Json<Task>,
) -> Result<Json<Task>, Custom<JsonValue>> {
    let id = id;
    let user_id = match ObjectId::parse_str(auth.sub){
        Ok(object_id) => Some(object_id),
        Err(_) => None,
    };
    if id.is_empty() {
        let json_response = json!({"error":"Id of task is requires"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    }
    let new_task_data = Task {
        id: None,
        task: new_task.task.to_owned(),
        description: new_task.description.to_owned(),
        reminder_date: new_task.reminder_date,
        user_id:Some(user_id.expect("REASON")),
        user_email:new_task.user_email.to_owned()
    };

    let new_task_detail = db.update_task(&id, &new_task_data);
    match new_task_detail {
        Ok(update) => {
            if update.matched_count == 1 {
                let updated_task = new_task_data;
                return Ok(Json(updated_task));
            } else {
                let json_response = json!({ "error": "No tasks was updated" });
                Err(Custom(Status::NotFound, json_response.into()))
            }
        }
        Err(_) => {
            let json_response = json!({ "error": "No tasks was updated" });
            Err(Custom(Status::NotFound, json_response.into()))
        }
    }
}

#[delete("/deletereminder/<id>")]
pub fn delete_reminder(db: &State<MongoRepo>, id: String) -> Result<Json<&str>, Custom<JsonValue>> {
    let id = id;
    println!("{}", id);
    if id.is_empty() {
        let json_response = json!({"error":"Id of task is requires"});
        return Err(Custom(Status::BadRequest, json_response.into()));
    };
    let deleted_task = db.delete_task(&id);
    println!("{:?}", deleted_task);
    match deleted_task {
        Ok(deleted) => {
            if deleted.deleted_count == 1 {
                return Ok(Json("Deleted task successfully"));
            } else {
                let json_response = json!({ "error": "No tasks was deleted" });
                Err(Custom(Status::NotFound, json_response.into()))
            }
        }
        Err(_) => {
            let json_response = json!({ "error": "No tasks was updated" });
            Err(Custom(Status::NotFound, json_response.into()))
        }
    }
}

use mongodb::bson::oid::ObjectId;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
#[derive(Debug, Serialize, Deserialize, Clone)]

pub struct Task{
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id : Option<ObjectId>,
    pub task : String,
    pub description : String,
    pub reminder_date: Option<DateTime<Utc>>,
    pub user_id : Option<ObjectId> ,//reference of the user model
    pub user_email : String
}
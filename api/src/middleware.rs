use actix_session::SessionExt;
use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    Error, HttpResponse,
};

pub async fn require_auth<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error> {
    let is_authenticated = req
        .get_session()
        .get::<u64>("user_id")
        .ok()
        .flatten()
        .is_some();

    if is_authenticated {
        next.call(req).await.map(|res| res.map_into_left_body())
    } else {
        let (req, _) = req.into_parts();
        Ok(ServiceResponse::new(
            req,
            HttpResponse::Unauthorized().body("Authentication required"),
        )
        .map_into_right_body())
    }
}



use ptrs;
use crate::obfs4::Client;


impl ptrs::client::T1 for Client {
    fn wrap() {}
}

#[cfg(test)]
mod test {

    async fn establish<T, E>(
        t: T,
        pt: impl ClientBuilderByTypeInst<T>,
    ) -> Result<PluggableTransportFut<T, E>, Box<dyn std::error::Error>> {
        let client = pt
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build();
        Ok(client.wrap(t))
    }

    #[tokio::test]
    async fn test_interface() -> Result<(), std::io::Error> {
        init_subscriber();
        let t_fut = tokio::net::TcpStream::connect("127.0.0.1:8080");

        let obfs_builder = obfs4::Builder();

        let conn = establish(t_fut, obfs_builder).await?;

        Ok(())
    }
}

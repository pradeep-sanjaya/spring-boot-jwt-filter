# spring-boot JWT token filter

- The token is obtained from Google oAuth2 from a spring-boot application
- Token obtained from Google oAuth2 is intercepted and logged in with the principal
- Obtaining a token through /authenticate is also implemented, but the validation is not done against generated token in the application

```
curl -X POST -H "Content-Type: application/json" -d '{"username": "sanjayangp@gmail.com", "password": "password"}' http://localhost:8080/authenticate

## Bearer token is not received from /authenticate
## Bearer token is received from a react client application
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0YmIyMjBjZDA5NGIwYWU5MGRkNzNlMTBjMTBlN2RiNTRiODkyODAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiNjQyNzQ2MTgxMjQ3LTJtM3N2ajBkb2o0MzIzYmw1ZGl2NWNoYzdhb3E5MnZ2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiNjQyNzQ2MTgxMjQ3LTJtM3N2ajBkb2o0MzIzYmw1ZGl2NWNoYzdhb3E5MnZ2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA0MTA2NTM4MTM4MDUzOTQ5NjY3IiwiaGQiOiJiYXl2aWV3dGVjaG5vbG9neS5jb20iLCJlbWFpbCI6InByYWRlZXAuc2FuamF5YUBiYXl2aWV3dGVjaG5vbG9neS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlVySU1VOTFGVkg3N1Ftd0J4MklFaGciLCJuYW1lIjoiUHJhZGVlcCBTYW5qYXlhIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hLS9BT2gxNEdoTnBrQ0dpVTQwck42Q0EzU0RTbUtJUjFYeDd2ZFVpN0tDbXZGOD1zOTYtYyIsImdpdmVuX25hbWUiOiJQcmFkZWVwIiwiZmFtaWx5X25hbWUiOiJTYW5qYXlhIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE2NDQ5NzE0MDAsImV4cCI6MTY0NDk3NTAwMCwianRpIjoiMzY0MDVkODI3NjBlMzljMmRkYzI2NGFiMzlkZDY1MDdjODBjYTFiMiJ9.H7itrX7q3WAJTC8CtxHd4kHg_j6ZmxTNU03Wgmtv4b29ILfW712i_3Af3wER6EIaXsMEnWTAGtqo2377ucQm1D4TGu43p3FK-KTbuQ0EypeHweuA1mR06knx3yAc6-dCdFT15MZB1QeP31IpSRs7F5tVc2-CldL0HA_xc8hVoYrqU2uJML_tkxIq_EdI8cnkEhhLbsIHJK1OiQ8tyP3Vexce_0qkSxhayx64peuVjWQPTiD3rWBl1eW0BJ1QLPbsWQ7Kz4L8t5BMvRTZWYTSRyc9OmVUIDyorOy9-OIDngL-CCNCYDurnc_2yqAghfiaTASyJ2Gq092I8tOt1lYD7g" http://localhost:8080/hello
```

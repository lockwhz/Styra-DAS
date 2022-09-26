package policy.ingress

default allow = false

# allow /finance/salary/{user} ingress
allow {
  some username
  input.attributes.request.http.method == "GET"
  input.parsed_path = ["finance", "salary", username]
}

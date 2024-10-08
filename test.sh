JWT_TOKEN_1="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRoaXMgaXMgb25lIiwiaWF0IjoxNTE2MjM5MDIyfQ.TKNxLvNd53GNtJbofpipBOLvZrxZWSfNOUfTh-9bm9E"
JWT_TOKEN_2="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRoaXMgaXMgdHdvIiwiaWF0IjoxNTE2MjM5MDIyfQ.7XS1JGZQzdlWRhTdYeaL0gf-IKr3S2EdjnRKSOm7MPs"

divider() {
  echo "----------------------------------------"
}

curl -H "Host: test.host.local" "http://localhost:83/" -i
divider
curl -H "Host: test.host.local" --cookie "jwt=$JWT_TOKEN_1" "http://localhost:83/" -i
divider
curl -H "Host: test.host.local" --cookie "client-jwt=$JWT_TOKEN_2" "http://localhost:83/" -i
divider
curl -H "Host: test.host.local" --cookie "jwt=$JWT_TOKEN_2" "http://localhost:83/" -i

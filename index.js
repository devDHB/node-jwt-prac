const cookieParser = require("cookie-parser");
const express = require("express");
const jwt = require("jsonwebtoken");

app = express();
const secretText = "superSecret";
const refreshSecretText = "supersuperSecret";

const posts = [
  {
    username: "Doo",
    title: "Post 1",
  },
  {
    username: "Kim",
    title: "Post 2",
  },
];

let refreshTokens = [];

app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send("Welcome");
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = { name: username };

  // jwt 토큰 생성하기 payload + secretText
  // 유효기간 추가
  const accessToken = jwt.sign(user, secretText, { expiresIn: "30s" });

  // jwt 이용해서 refreshtoken 생성
  const refreshToken = jwt.sign(user, refreshSecretText, { expiresIn: "1d" });
  refreshTokens.push(refreshToken);

  // refresh token 을 쿠키에 저장
  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ accessToken: accessToken });
});

app.get("/posts", authMiddleware, (req, res) => {
  res.json(posts);
});

function authMiddleware(req, res, next) {
  // 토큰을 request headers에서 가져오기
  const authHeader = req.headers["authorization"];
  // Bearer 가져오기
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return res.sendStatus(401);
  }
  // 토큰이 있으니 유효한 토큰인지 확인
  jwt.verify(token, secretText, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get("/refresh", (req, res) => {
  // console.log("req.cookies", req.cookies);
  // res.sendStatus(200);

  // cookies 가져오기
  const cookies = req.cookies;
  if (!cookies?.jwt) {
    return res.sendStatus(403);
  }

  const refreshToken = cookies.jwt;
  // refresh token 이 db에 있는 토큰인지 확인
  if (!refreshToken.includes(refreshToken)) {
    return res.sendStatus(403);
  }

  // token 이 유효한 토큰인지 호가인
  jwt.verify(refreshToken, refreshSecretText, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    // access token 생성
    const accessToken = jwt.sign({ name: user.name }, secretText, {
      expiresIn: "30s",
    });
    res.json({ accessToken: accessToken });
  });
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(port + "포트로 시작");
});

# NothingToGlad
# Git manual
Project của mình có 2 luồng là ORIGIN và UPSTREAM

Đầu tiên fork project chính về tài khoản git của mình ở link : https://github.com/taind/NothingToGlad

clone project về máy mình
```
git clone https://github.com/taind/NothingToGlad
```
ta tiến hình config username và email
```
git config user.name "username"
git config user.email "email@email.com"
```
add luồng upstream
```
git remote add upstream https://github.com/taind/NothingToGlad
```
Kiểm tra lại bằng cách:
```
git remote -v 
```
hiện ra 4 dòng, trong đó có 2 dòng là orign và 2 dòng là upstream

dòng upstream có link https://github.com/taind/NothingToGlad

dòng origin có link   https://github.com/[user của bạn]/NothingToGlad

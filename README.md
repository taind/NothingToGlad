# NothingToGlad
# Git manual
Project của mình có 2 luồng là ORIGIN và UPSTREAM

---- Phần này làm lúc clone project về lần đầu ----

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
tạo branch develop mới 
```
git branch develop
git checkout develop
```
hiện ra 4 dòng, trong đó có 2 dòng là orign và 2 dòng là upstream

dòng upstream có link https://github.com/taind/NothingToGlad

dòng origin có link   https://github.com/[user của bạn]/NothingToGlad

vậy tác dụng của nó là gì, luồng origin để PUSH còn luồng upstream để PULL

mỗi khi project chính được update thì chủ project sẽ hô lên để anh em PULL code mới về

----xong phần mở đầu-----

----PHẦN NÀY TA SẼ LÀM THƯỜNG XUYÊN

lệnh để pull code mới, khi có hiệu lệnh bắt buộc phải pull code mới về
```
git status //check thử mình có đang thay đổi gì ko
git add . // nếu có thì add nó
git commit -m "doing messga" //commit lại
git pull upstream develop  // pull code mới về
```
làm các bước như trên để tránh bị conflict cùng 1 dòng mà có 2 người sửa.

tương tự sau khi bạn có thay đổi trong project trên máy, dấu chấm là tất cả các file có thay đổi
```
git status
git add .
git commit -m "message" // nếu thiếu commit thì sẽ ko push lên đc đâu
git push origin develop // nó sẽ hỏi username và password của bạn đó
```
sau đó lên github tạo pull request, chọn branch là develop

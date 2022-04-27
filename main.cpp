#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>


using namespace std;

class Policy{
protected:
    bool isChecked;
public:
    virtual void check(const std::string &password) = 0;

    bool getCheck() const{
        return isChecked;
    }
};

class LengthPolicy : public Policy{
private:
    uint16_t minLength;
    uint16_t maxLength;
public:
    LengthPolicy(uint16_t min){
        minLength = min;
        maxLength = 255;
    }

    LengthPolicy(uint16_t min, uint16_t max){
        minLength = min;
        maxLength = max;
    }

    virtual void check(const std::string &password){
        if(maxLength == 255){
            if(password.size() >= minLength){
                this->isChecked = true;
            } else this->isChecked = false;
        } else {
            if(password.size() >= minLength && password.size() <= maxLength){
                this->isChecked = true;
            } else this->isChecked = false;
        }
    };
};

class ClassPolicy : public Policy{
private:
    uint16_t minClassCount;
public:
    ClassPolicy(uint16_t count){
        minClassCount = count;
    }

    virtual void check(const std::string &password){
        int k = 0, cnt = 0;
        for(char h : password){
            if(isupper(h)){
                k++;
            }
        }
        if(k > 0){
            cnt++;
        }
        k = 0;
        for(char h : password){
            if(islower(h)){
                k++;
            }
        }
        if(k > 0){
            cnt++;
        }
        k = 0;
        for(char h : password){
            if(h == '!' || h == '@' || h == '#' || h == '$' || h == '%' || h == '^' || h == '&' || h == '*'){
                k++;
            }
        }
        if(k > 0){
            cnt++;
        }
        k = 0;
        for(char h : password){
            if(isdigit(h)){
                k++;
            }
        }
        if(k > 0){
            cnt++;
        }
        k = 0;
        if(cnt >= minClassCount){
            this->isChecked = true;
        } else this->isChecked = false;
    };
};

class IncludePolicy : public Policy{
private:
    char characterType;
public:
    IncludePolicy(char type){
        characterType = type;
    }

    virtual void check(const std::string &password){
        if(characterType == 'A'){
            int k = 0;
            for(char h : password){
                if(isupper(h)){
                    k++;
                }
            }
            if(k >= 1){
                this->isChecked = true;
            } else this->isChecked = false;
        }
        if(characterType == 'a'){
            int k = 0;
            for(char h : password){
                if(islower(h)){
                    k++;
                }
            }
            if(k >= 1){
                this->isChecked = true;
            } else this->isChecked = false;
        }
        if(characterType == '0'){
            int k = 0;
            for(char h : password){
                if(isdigit(h)){
                    k++;
                }
            }
            if(k >= 1){
                this->isChecked = true;
            } else this->isChecked = false;
        }
        if(characterType == '$'){
            int k = 0;
            for(char h : password){
                if(h == '!' || h == '@' || h == '#' || h == '$' || h == '%' || h == '^' || h == '&' || h == '*'){
                    k++;
                }
            }
            if(k >= 1){
                this->isChecked = true;
            } else this->isChecked = false;
        }
    }
};

class NotIncludePolicy : public Policy{
private:
    char characterType;
public:
    NotIncludePolicy(char type){
        characterType = type;
    }

    virtual void check(const std::string &password){
        if(characterType == 'A'){
            int k = 0;
            for(char h : password){
                if(isupper(h)){
                    k++;
                }
            }
            if(k >= 1){
                this->isChecked = false;
            } else this->isChecked = true;
        }
        if(characterType == 'a'){
            int k = 0;
            for(char h : password){
                if(islower(h)){
                    k++;
                }
            }
            if(k >= 1){
                this->isChecked = false;
            } else this->isChecked = true;
        }
        if(characterType == '0'){
            int k = 0;
            for(char h : password){
                if(isdigit(h)){
                    k++;
                }
            }
            if(k >= 1){
                this->isChecked = false;
            } else this->isChecked = true;
        }
        if(characterType == '$'){
            int k = 0;
            for(char h : password){
                if(h == '!' || h == '@' || h == '#' || h == '$' || h == '%' || h == '^' || h == '&' || h == '*'){
                    k++;
                }
            }
            if(k >= 1){
                this->isChecked = false;
            } else this->isChecked = true;
        }
    }
};

class RepetitionPolicy : public Policy{
private:
    uint16_t maxCount;
public:
    RepetitionPolicy(uint16_t count){
        maxCount = count;
    }

    virtual void check(const std::string &password){
        int cnt = 0, k = 1;
        std::vector<char> words;
        for(char h : password){
            words.push_back(h);
        }
        for(int i = 0; i < words.size(); i++){
            for(int j = i; j < words.size(); j++){
                if(words[i] == words[j]){
                    cnt++;
                }
            }
            if(cnt >= k){
                k = cnt;
            }
            cnt = 0;
        }
        if(k <= maxCount){
            this->isChecked = true;
        } else this->isChecked = false;
    }
};

class ConsecutivePolicy : public Policy{
private:
    uint16_t maxCount;
public:
    ConsecutivePolicy(uint16_t count){
        maxCount = count;
    }

    virtual void check(const std::string &password){
        std::vector<uint16_t> passNumb;
        for(char h : password){
            passNumb.push_back(h);
        }
        int cnt = 1, k = 0;
        for(int i = 0; i < passNumb.size(); i++){
            cnt = 1;
            int o = 1;
            for(int j = i + 1; j < passNumb.size(); j++){
                if(passNumb[j] == passNumb[i] + o){
                    cnt++;
                } else {
                    break;
                }
                if(cnt >= k){
                    k = cnt;
                }
                o++;
            }

        }
        if(k <= maxCount){
            this->isChecked = true;
        } else this->isChecked = false;

    }
};

std::string checkPassword(std::string pass, std::vector<Policy*> policies){
    int cnt = 0;
    for(int i = 0; i < policies.size(); i++){
        policies[i]->check(pass);
        if(policies[i]->getCheck() == false){
            cnt++;
        }
    }
    if(cnt == 0){
        return "OK";
    } else return "NOK";
}

int main(){
    int n, nr, numar;
    char k;
    cin >> n;
    vector<Policy*> policies;
    string rules, pass;
    for(int i = 0; i < n; i++){
        cin >> rules;
        if(rules == "length"){
            cin >> nr;
            if(scanf("%d", &numar) == 1){
                policies.push_back(new LengthPolicy(nr, numar));
            } else policies.push_back(new LengthPolicy(nr));
        }
        if(rules == "class"){
            cin >> nr;
            policies.push_back(new ClassPolicy(nr));
        }
        if(rules == "include"){
            cin >> k;
            policies.push_back(new IncludePolicy(k));
        }
        if(rules == "ninclude"){
            cin >> k;
            policies.push_back(new NotIncludePolicy(k));
        }
        if(rules == "repetition"){
            cin >> nr;
            policies.push_back(new RepetitionPolicy(nr));
        }
        if(rules == "consecutive"){
            cin >> nr;
            policies.push_back(new  ConsecutivePolicy(nr));
        }
    }
    while(cin >> pass){
        cout << checkPassword(pass, policies) << std::endl;
    }
    return 0;
}
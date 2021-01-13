
#include<bits/stdc++.h>
using namespace std;

int main(){
    int N ,i ;
    freopen("list.txt", "r", stdin); 
    freopen("output.txt", "w", stdout);
    cin >> N;
    string str[N];
    for(i = 0 ; i < N;i++)
        getline(cin, str[i]);
    sort(str , str + N);
    for(i = 0 ; i < N;i++)
        cout <<  str[i] << "\n";
}

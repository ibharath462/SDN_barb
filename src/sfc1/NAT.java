package sfc1;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class NAT {
    //static int count = 0;
    Scanner scan=new Scanner(System.in);
    Random rand=new Random();
    int flag=0;
    public void start(){
        AddressTranslation nat=new AddressTranslation();
        for(int i=0;i<256;i++){

        }
        while(flag==0){
            System.out.println("Enter your choice:");//1 for getting public ip assigned for a private ip and 2 for releasing one of assigned ip
            int ch=scan.nextInt();
            switch(ch){
                case 1:
                    /*if(count > 255)
                    {
                        nat.releaseIp();
                    }*/
                    int ip=rand.nextInt(256);//for a local place with 256 private ip addressess
                    int port=rand.nextInt(65536);//assume 65536 ports can be used to send to nat
                    String privateIp="192.0.0."+ip+":"+port;
                    nat.assignIp(privateIp);
                    break;
                case 2:
                    nat.releaseIp();//also to manually remove assigned public ip
                    break;
            }
        }
    }
    public static void main(String[] args) {
        NAT nat1=new NAT();
        nat1.start();
    }
}

class AddressTranslation{
    ConcurrentHashMap<Integer,String> myMap = new ConcurrentHashMap<Integer,String>();
    public void assignIp(String privateIp)
    {
        if(myMap.containsValue(privateIp)){//ig aready public ip is assigned for the particular private ip
            for(Integer port:myMap.keySet()){
                if(myMap.get(port)==privateIp){
                    System.out.println("Public IP:215.200.120.1:"+ port+"Private IP: "+privateIp);//one public ip with many or 65536 ports
                }
            }
        }
        else{                               //else assign new public ip
            for(int i=0;i<65536;i++)
            {
                if(myMap.get(i)==null)
                {
                    myMap.put(i, privateIp);
                    System.out.println("Public IP:215.200.120.1:"+ i+"Private IP: "+privateIp);
                    NAT n1 = new NAT();
                   // n1.count++;
                    break;
                }
            }
        }
    }
 /*   public void releaseIp(String privateIp){
        if(myMap.containsValue(privateIp)){
            for(Integer port:myMap.keySet()){
                if(myMap.get(port)==privateIp){
                    myMap.remove(port);
                    System.out.println("Released public ip is 215.200.120.1:"+ port);
                }
            }
        }
    }*/
    public void releaseIp(){             //releases the public ip assigned previously for a private ip
        for(Integer port:myMap.keySet()){
            if(myMap.get(port)!=null){
                myMap.remove(port);
                System.out.println("Released public ip is 215.200.120.1:"+ port);
                NAT n2 = new NAT();
                //n2.count--;
                break;
            }
        }
    }
}
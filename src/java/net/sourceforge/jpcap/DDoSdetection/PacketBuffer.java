/**--------------GNU-GPL v2------------------------
Detection Denial of service attack on the network.
The attack covered are ICMP, TCP Sync and UDP flood.
Method used for developing algorithm is PATTEREN Classification and DATA mining using tools "Weka".
Author:Mohnish Awade
       Anup Ingle
	  Mayank Gupta
Period: 27-july-2011 to 12-april-2012


*/

package pack;

import jpcap.packet.*;
import java.util.*;
import javax.swing.JOptionPane;
public class PacketBuffer implements Runnable
{
    private ArrayList<IPPacket> packetbufforlist=null;
    private ArrayList<IPPacket> temppacketbuffor=null;
    private static PacketBuffer pb=null;
    private static boolean  attackflag=false;
    private static int count=1;
    private static int arraybuffersize=20;
    //static int icmpconditioncounter=0;
    //private static int icmpconditioncounter;
    private static final int ICMP_PACKET_CODE = 41;
    
    Thread t = null;
    
    private PacketBuffer()
    {
        packetbufforlist=new ArrayList<IPPacket>();
        temppacketbuffor=new ArrayList<IPPacket>();
        t=new Thread(this,"logic thread");
        t.start();
    }
    public static synchronized PacketBuffer getInstanceMethod()
    {
        if(pb==null)
        {
            pb=new PacketBuffer();
        }        
        return pb;
    }
    public synchronized void  addPacket(IPPacket ip)
    {
        packetbufforlist.add(ip);
        //System.out.println(packetbufforlist.size()+"m");
    }
    public void run()
    {
        int startlimit=0,endlimit=arraybuffersize;
        while(true)
        {    
            if(packetbufforlist.size()>endlimit)
            {
                checkArrayBuffor(startlimit);
                startlimit++;
                endlimit++;
                count++;
                if(attackflag==true)
                {
                    break;//remove to repeat the thread
                }
            }
            
            
        }
    }
    public void checkArrayBuffor(int startlimit)
    {
        
        int loopcount;
        IPPacket iparr[]=new IPPacket[arraybuffersize];
        for(loopcount=0;loopcount<arraybuffersize;loopcount++)
        {        
            iparr[loopcount]=packetbufforlist.get(startlimit);
            startlimit++;
        }
        int j=0;
        while(j<arraybuffersize-3)
        {
            if((iparr[j].protocol==6) && (iparr[j] instanceof TCPPacket))
            {
                if(((TCPPacket)iparr[j]).syn==true && ((TCPPacket)iparr[j]).ack==false && ((TCPPacket)iparr[j]).rst==false)
                {
                    if((iparr[j+1].protocol==6) && (iparr[j+1] instanceof TCPPacket))
                    {
                        if(((TCPPacket)iparr[j+1]).syn==true && ((TCPPacket)iparr[j+1]).ack==true && ((TCPPacket)iparr[j+1]).rst==false)
                        {
                            if((iparr[j+2].protocol==6) && (iparr[j+2] instanceof TCPPacket))
                            {
                                if(((TCPPacket)iparr[j+2]).syn==false && ((TCPPacket)iparr[j+2]).ack==false && ((TCPPacket)iparr[j+2]).rst==true)
                                {
                                    System.out.println("tcp");
                                    tempBufforFill(j,"tcp");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            if(iparr[j].protocol==1)
            {
                if(iparr[j] instanceof ICMPPacket)
                {
                    int icmpbyte=((ICMPPacket)iparr[j]).code;
                    
                    if(icmpbyte>ICMP_PACKET_CODE)
                    {
                        if(iparr[j+1].protocol==17)
                        {
                            if(iparr[j+2].protocol==1)
                            {
                                //System.out.println("j+count"+(j+count-1));
                                tempBufforFillforicmp(j,"icmp");
                                if(attackflag==true)
                                {
                                    break;
                                }
                            }
                            if(iparr[j+2].protocol==17)
                            {
                                if(iparr[j+3].protocol==1)
                                {
                                   // System.out.println("icmp2");
                                    //System.out.println(j+count-1);
                                    tempBufforFillforicmp(j,"icmp");
                                    if(attackflag==true)
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if(iparr[j].protocol==17)
            {
                if(iparr[j+1].protocol==1)
                {
                    if(iparr[j+2].protocol==17)
                    {
                        tempBufforFillforudp(j,"udp");
                        if(attackflag==true)
                        {
                            break;
                        }
                    }
                }
            }
            j++;
        }
        
    }
    public void tempBufforFill(int no,String protocolname)
    {
        while(true)
        {
            if(packetbufforlist.size()>no+count)
            {
                temppacketbuffor.add(packetbufforlist.get(no+count));
                no++;
            }
            if(temppacketbuffor.size()>100)
            {    
                System.out.println(protocolname+" attack");
                JOptionPane.showMessageDialog(null,protocolname+" attack");
                attackflag=true;
                break;
            }
        }
    }
    
    public void tempBufforFillforudp(int no,String protocolname)
    {
        while(true)
        {
            if(packetbufforlist.size()>no+count)
            {   
                temppacketbuffor.add(packetbufforlist.get(no+count-1));
                no++;
                
            }   
            if(temppacketbuffor.size()>100)
            break;
        }
        int loopcounter=0;
        int conditioncounter=0;
        while(loopcounter<97)
        {
            if(temppacketbuffor.get(loopcounter).protocol==17)
            {
                if(temppacketbuffor.get(loopcounter+1).protocol==1)
                    {
                        if(temppacketbuffor.get(loopcounter+2).protocol==17)
                        {
                            
                            loopcounter++;
                            conditioncounter++;
                            if(conditioncounter>40)
                            {
                                System.out.println(protocolname+" attack");
                                JOptionPane.showMessageDialog(null,protocolname+" attack");
                                attackflag=true;
                                break;
                            }
                        }
                    }
            }
            loopcounter++;
            
        }
    }
    public void tempBufforFillforicmp(int no,String protocolname)
    {
        while(true)
        {
            if(packetbufforlist.size()>no+count)
            {   
                temppacketbuffor.add(packetbufforlist.get(no+count-1));
                no++;
                
            }
            if(temppacketbuffor.size()>=100)
            break;
        }
        int loopcounter=0;
        int icmpconditioncounter=0;
        while(loopcounter<96)
        {
            if(temppacketbuffor.get(loopcounter).protocol==1)
            {
                if(temppacketbuffor.get(loopcounter) instanceof ICMPPacket)
                {
                    int packcode=41;
                    int icmpbyte=((ICMPPacket)temppacketbuffor.get(loopcounter)).code;
                    
                    if(icmpbyte>packcode)
                    {
                        if(temppacketbuffor.get(loopcounter+1).protocol==17)
                        {
                            if(temppacketbuffor.get(loopcounter+2).protocol==17)
                            {
                                if(temppacketbuffor.get(loopcounter+3).protocol==1)
                                {
                                    //System.out.println("l1"+loopcounter);
                                    loopcounter+=3;
                                    if(icmpconditioncounter>20)
                                    {
                                        System.out.println(protocolname+" attack");
                                        JOptionPane.showMessageDialog(null,protocolname+" attack");
                                        attackflag=true;
                                        break;
                                    }
                                }
                            }
                            if(temppacketbuffor.get(loopcounter+2).protocol==1)
                            {
                                //System.out.println("l2"+loopcounter);
                                //System.out.println(icmpconditioncounter);
                                icmpconditioncounter++;
                                loopcounter+=2;
                                if(icmpconditioncounter>20)
                                {
                                System.out.println(protocolname+" attack");
                                JOptionPane.showMessageDialog(null,protocolname+" attack");
                                attackflag=true;
                                break;
                                }
                            }
                            
                        }
                    }
                }
            }
            loopcounter++;
            //System.out.println("looop"+loopcounter);
            
        }
    }
    
}

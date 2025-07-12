# SiriusXM

This is forked from andrew0 with minimal changes:

* Updated SXM auth cookie name (so that the system actually authenticates now...)
  * 20240131 And changed it again...
* Updated AWS cookie name (again, so that it actually authenticates again...)
* Added -e (--env) parameter to use SXM_USER and SXM_PASS environment variables to override username and password on command line
  * Note: The username and password parameters are still required:  just put something like "user" and "pass".
* I added a generic systemd unit file and an override file customized for my use case.
    
Original Readme:

This script creates a server that serves HLS streams for SiriusXM channels. To use it, pass your SiriusXM username and password and a port to run the server on. For example, you start the server by running:
`python3 sxm.py myuser mypassword -p 8888`

You can see a list of the channels by setting the -l or --list flag:
`python3 sxm.py myuser mypassword -l`

If you are in Canada then add --canada to the command line

Then in a player that supports HLS (QuickTime, VLC, ffmpeg, etc) you can access a channel at http://127.0.0.1:8888/channel.m3u8 where "channel" is the channel name, ID, or Sirius channel number.

Here's a list of some of the channel IDs:
```
ID                  | Num | Name
-----------------------------------------------                        
siriushits1         | 2   | SiriusXM Hits 1              
coffeehouse         | 3   | The Coffee House             
9544                | 4   | TikTok Radio                 
thepulse            | 5   | The Pulse                    
9450                | 6   | PopRocks                     
totally70s          | 7   | 70s on 7                     
big80s              | 8   | 80s on 8                     
8206                | 9   | 90s on 9                     
8208                | 10  | Pop2K                        
9556                | 11  | The 10s Spot                 
9608                | 12  | The Kelly Clarkson Connection
9406                | 13  | Pitbull's Globalization      
9614                | 14  | Life with John Mayer         
9557                | 15  | Mosaic                       
starlite            | 16  | The Blend                    
9624                | 17  | The GRAMMY Channel           
9446                | 18  | The Beatles Channel          
9523                | 19  | Bob Marley's Tuff Gong       
estreetradio        | 20  | E Street Radio               
undergroundgarage   | 21  | Underground Garage           
8370                | 22  | Pearl Jam Radio              
gratefuldead        | 23  | Grateful Dead                
radiomargaritaville | 24  | Radio Margaritaville         
classicrewind       | 25  | Classic Rewind               
classicvinyl        | 26  | Classic Vinyl                
thebridge           | 27  | The Bridge                   
thespectrum         | 28  | The Spectrum                 
9139                | 29  | Phish Radio                  
9506                | 30  | Dave Matthews Band Radio     
9407                | 31  | Tom Petty Radio              
9507                | 32  | U2 X-Radio                   
firstwave           | 33  | 1st Wave                     
90salternative      | 34  | Lithium                      
leftofcenter        | 35  | SiriusXMU                    
altnation           | 36  | Alt Nation                   
octane              | 37  | Octane                       
buzzsaw             | 38  | Ozzy's Boneyard              
hairnation          | 39  | Hair Nation                  
hardattack          | 40  | Liquid Metal                 
9413                | 41  | SiriusXM Turbo               
9524                | 42  | Sound 42                     
9471                | 43  | Rock The Bells Radio         
hiphopnation        | 44  | Hip-Hop Nation               
shade45             | 45  | Shade 45                     
hotjamz             | 46  | The Heat                     
heartandsoul        | 47  | Heart & Soul                 
9609                | 48  | The Flow                     
9610                | 49  | Flex2K                       
9339                | 50  | SiriusXM FLY                 
8228                | 51  | The Groove                   
thebeat             | 52  | BPM                          
9472                | 53  | Diplo's Revolution           
9145                | 54  | Studio 54 Radio              
chill               | 55  | SiriusXM Chill               
newcountry          | 56  | The Highway                  
9340                | 57  | Y2Kountry                    
primecountry        | 58  | Prime Country                
9418                | 59  | No Shoes Radio               
9599                | 60  | Carrie's Country             
theroadhouse        | 61  | Willie's Roadhouse           
outlawcountry       | 62  | Outlaw Country               
9607                | 63  | Chris Stapleton Radio        
praise              | 64  | Kirk Franklin's Praise       
spirit              | 65  | The Message                  
jazzcafe            | 66  | Watercolors                  
purejazz            | 67  | Real Jazz                    
spa73               | 68  | Spa                          
broadwaysbest       | 69  | On Broadway                  
siriuslysinatra     | 70  | Siriusly Sinatra             
8205                | 71  | 40s Junction                 
siriusgold          | 72  | 50s Gold                     
60svibrations       | 73  | 60s Gold                     
soultown            | 74  | Smokey's Soul Town           
siriusblues         | 75  | BB King's Bluesville         
elvisradio          | 76  | Elvis Radio                  
bluegrass           | 77  | Bluegrass Junction           
symphonyhall        | 78  | Symphony Hall                
9353                | 79  | The Billy Joel Channel       
espnradio           | 80  | ESPN Radio                   
8254                | 81  | ESPN Xtra                    
8213                | 82  | Mad Dog Sports Radio         
9445                | 83  | FOX Sports on SiriusXM       
siriussportsaction  | 84  | College Sports Radio         
9525                | 85  | NBC Sports Audio             
9385                | 86  | SiriusXM NBA Radio           
8368                | 87  | Fantasy Sports Radio         
siriusnflradio      | 88  | SiriusXM NFL Radio           
8333                | 89  | MLB Network Radio            
siriusnascarradio   | 90  | SiriusXM NASCAR Radio        
8185                | 91  | NHL Network Radio            
8186                | 92  | SiriusXM PGA TOUR Radio      
9494                | 93  | Netflix Is A Joke Radio      
9408                | 94  | Comedy Greats                
9356                | 95  | Comedy Central Radio         
9469                | 96  | KevinHart Laugh Out Loud     
bluecollarcomedy    | 97  | Comedy Roundup               
laughbreak          | 98  | Pure Comedy                  
rawdog              | 99  | Raw Comedy                   
howardstern100      | 100 | Howard 100                   
howardstern101      | 101 | Howard 101                   
9409                | 102 | Radio Andy                   
8184                | 103 | Faction Talk                 
9580                | 104 | Conan O'Brien Radio          
9351                | 105 | SiriusXM 105                 
9638                | 107 | Dateline 24/7                
9390                | 108 | TODAY Show Radio             
siriusstars         | 109 | Stars                        
doctorradio         | 110 | Doctor Radio                 
9449                | 111 | Triumph                      
cnbc                | 112 | CNBC                         
9369                | 113 | FOX Business                 
foxnewschannel      | 114 | FOX News Channel             
9410                | 115 | FOX News Headlines 24/7      
cnn                 | 116 | CNN                          
cnnheadlinenews     | 117 | HLN                          
8367                | 118 | MSNBC                        
bbcworld            | 120 | BBC World Service            
bloombergradio      | 121 | Bloomberg Radio              
nprnow              | 122 | NPR Now                      
8239                | 123 | PRX Remix                    
indietalk           | 124 | POTUS Politics               
siriuspatriot       | 125 | SiriusXM Patriot             
8238                | 126 | SiriusXM Urban View          
siriusleft          | 127 | SiriusXM Progress            
9392                | 128 | Joel Osteen Radio            
thecatholicchannel  | 129 | The Catholic Channel         
ewtnglobal          | 130 | EWTN Radio                   
8307                | 131 | Family Talk                  
9359                | 132 | Business Radio               
9530                | 133 | Disney Hits                  
8216                | 134 | Kids Place                   
9366                | 135 | KIDZ BOP Radio               
9600                | 136 | Moonbug Radio                
9133                | 140 | Holy Culture Radio           
9129                | 141 | HUR Voices                   
9130                | 142 | HBCU                         
9131                | 143 | BYUradio                     
9132                | 144 | Korea Today                  
9411                | 145 | SLAM Radio                   
roaddogtrucking     | 146 | Road Dog Trucking            
9367                | 147 | RURAL Radio                  
radioclassics       | 148 | RadioClassics                
8215                | 149 | Escape                       
8229                | 150 | Bill Gaither's enLighten     
9593                | 151 | Hits Uno                     
rumbon              | 152 | Caliente                     
9186                | 153 | Águila                       
9135                | 154 | En Vivo                      
9134                | 155 | Latin Vault                  
8230                | 156 | SiriusXM Fight Nation        
9341                | 157 | SiriusXM FC                  
9448                | 158 | VSiN                         
9512                | 159 | SportsGrid                   
9582                | 163 | Attitude Franco              
9583                | 164 | Mixtape: North               
9358                | 165 | The Indigiverse              
9584                | 166 | Racines Musicales            
9172                | 167 | Canada Talks                 
8259                | 168 | SiriusXM Comedy Club         
cbcradioone         | 169 | CBC Radio One                
premiereplus        | 170 | ICI Première                 
9585                | 171 | Top of the Country Radio     
8248                | 172 | SiriusXM Scoreboard          
8244                | 173 | The Verge                    
8246                | 174 | Influence Franco             
8256                | 218 | SiriusXM INDYCAR Nation      
9415                | 301 | Road Trip Radio              
9543                | 302 | Andy Cohen's Kiki Lounge     
9492                | 303 | Pandora Now                  
thevault            | 308 | Deep Tracks                  
jamon               | 309 | Jam On 309                   
9420                | 311 | Yacht Rock 311               
9547                | 312 | Bon Jovi Radio               
9611                | 313 | Alt2K                        
faction             | 314 | FACTION PUNK                 
9570                | 315 | Red Hot Chili Peppers        
9364                | 330 | SiriusXM Silk 330            
reggaerhythms       | 332 | Shaggy Boombastic Radio      
9623                | 340 | Radio Monaco                 
9365                | 341 | Utopia                       
9475                | 349 | Bakersfield Beat             
9178                | 350 | Red White & Booze            
9468                | 359 | North Americana              
9414                | 362 | Grown Folk JAMZ              
9493                | 370 | ESPN Podcasts                
9455                | 371 | SiriusXM ACC Radio           
9459                | 372 | SiriusXM Big Ten Radio       
9458                | 374 | SiriusXM SEC Radio           
9473                | 375 | Infinity Sports Network      
9514                | 453 | CNN Originals                
9454                | 454 | CNN International            
8237                | 455 | C-SPAN Radio                 
9479                | 460 | The Billy Graham Channel     
9481                | 501 | Limited Edition 1            
9545                | 502 | Limited Edition 2            
9546                | 503 | Limited Edition 3            
9398                | 504 | Limited Edition 4            
9399                | 505 | Limited Edition 5            
9400                | 506 | Limited Edition 6            
9401                | 507 | Limited Edition 7            
9402                | 508 | Limited Edition 8            
9403                | 509 | Limited Edition 9            
9548                | 510 | Limited Edition 10           
9549                | 511 | Limited Edition 11           
9482                | 512 | Limited Edition 12           
9572                | 550 | Pop Top 500                  
9573                | 551 | 80s on 8 Top 500             
9574                | 552 | 90s on 9 Top 500             
9575                | 553 | Classic Rock Top 1000        
9577                | 556 | Hip-Hop Top 500              
9576                | 558 | Country Top 1000             
9571                | 560 | Billboard Top 500            
9342                | 602 | Holiday Traditions           
9634                | 702 | Disney Jr. Radio             
9378                | 703 | Oldies Party                 
9500                | 704 | SoulCycle Radio              
9502                | 705 | SiriusXM K-Pop               
siriuslove          | 708 | SiriusXM Love                
8207                | 710 | The Loft                     
9352                | 711 | Petty's Buried Treasure      
9470                | 712 | Marky Ramone's Punk Rock     
9175                | 713 | RockBar                      
9375                | 715 | Classic Rock Party           
9397                | 720 | Sway's Universe              
9558                | 721 | Stevie's Coolest Songs       
9541                | 723 | RTB - Mixdown                
9564                | 724 | SoundCloud Radio             
9526                | 735 | Steve Aoki's Remix Radio     
9527                | 736 | A State of Armin             
9633                | 737 | Avicii Radio                 
9630                | 739 | Savior Sunday Daily          
9590                | 740 | Outsiders Radio              
8227                | 741 | The Village                  
metropolitanopera   | 744 | Met Opera Radio              
siriuspops          | 745 | SiriusXM Pops                
9569                | 747 | Miles Davis Radio            
9511                | 754 | Poplandia                    
9501                | 757 | The Tragically Hip Radio     
9513                | 758 | Iceberg                      
energie2            | 759 | Les Tubes Franco             
9529                | 760 | Chucho's Cuba & Beyond       
9188                | 762 | Caricia                      
8225                | 763 | Viva                         
9187                | 764 | Latidos                      
9185                | 765 | Flow Nación                  
9189                | 766 | Luna                         
9190                | 767 | Rumbón                       
9191                | 768 | La Kueva                     
9503                | 771 | She's So Funny               
9542                | 772 | Comedy Classics              
9592                | 779 | Mental Health Radio          
9597                | 781 | SiriusXM App Originals       
9636                | 787 | SmartLess Radio              
9632                | 788 | Crime Junkie Radio           
9601                | 789 | The Jeff Lewis Channel       
9405                | 790 | Entertainment Now            
9565                | 791 | Freakonomics Radio           
9443                | 792 | Ramsey Network               
9581                | 793 | Law&Crime                    
cnnespanol          | 795 | CNN en Español               
9491                | 796 | ATN                          
9639                | 798 | NBC News NOW                 
9637                | 799 | The Weather Channel          
9146                | 800 | Arizona Cardinals            
9147                | 801 | Atlanta Falcons              
9148                | 802 | Baltimore Ravens             
9149                | 803 | Buffalo Bills                
9150                | 804 | Carolina Panthers            
9151                | 805 | Chicago Bears                
9152                | 806 | Cincinnati Bengals           
9153                | 807 | Cleveland Browns             
9154                | 808 | Dallas Cowboys               
9155                | 809 | Denver Broncos               
9156                | 810 | Detroit Lions                
9157                | 811 | Green Bay Packers            
9158                | 812 | Houston Texans               
9159                | 813 | Indianapolis Colts           
9160                | 814 | Jacksonville Jaguars         
9161                | 815 | Kansas City Chiefs           
9168                | 816 | Las Vegas Raiders            
9171                | 817 | Los Angeles Chargers         
9203                | 818 | Los Angeles Rams             
9162                | 819 | Miami Dolphins               
9163                | 820 | Minnesota Vikings            
9164                | 821 | New England Patriots         
9165                | 822 | New Orleans Saints           
9166                | 823 | New York Giants              
9167                | 824 | New York Jets                
9169                | 825 | Philadelphia Eagles          
9170                | 826 | Pittsburgh Steelers          
9202                | 827 | San Francisco 49ers          
9201                | 828 | Seattle Seahawks             
9204                | 829 | Tampa Bay Buccaneers         
9205                | 830 | Tennessee Titans             
9206                | 831 | Washington Commanders        
9594                | 832 | NFL en Español 832           
9231                | 840 | Arizona Diamondbacks         
9232                | 841 | Atlanta Braves               
9233                | 842 | Baltimore Orioles            
9234                | 843 | Boston Red Sox               
9235                | 844 | Chicago Cubs                 
9236                | 845 | Chicago White Sox            
9237                | 846 | Cincinnati Reds              
9238                | 847 | Cleveland Guardians          
9239                | 848 | Colorado Rockies             
9240                | 849 | Detroit Tigers               
9241                | 850 | Houston Astros               
9242                | 851 | Kansas City Royals           
9243                | 852 | Los Angeles Angels           
9244                | 853 | Los Angeles Dodgers          
9245                | 854 | Miami Marlins                
9246                | 855 | Milwaukee Brewers            
9247                | 856 | Minnesota Twins              
9248                | 857 | New York Mets                
9249                | 858 | New York Yankees             
9250                | 859 | Oakland Athletics            
9251                | 860 | Philadelphia Phillies        
9252                | 861 | Pittsburgh Pirates           
9253                | 862 | San Diego Padres             
9254                | 863 | San Francisco Giants         
9255                | 864 | Seattle Mariners             
9256                | 865 | St. Louis Cardinals          
9257                | 866 | Tampa Bay Rays               
9258                | 867 | Texas Rangers                
9259                | 868 | Toronto Blue Jays            
9260                | 869 | Washington Nationals         
9595                | 870 | MLB en Español 870           
9596                | 871 | MLB en Español 871           
9266                | 880 | Atlanta Hawks                
9268                | 881 | Boston Celtics               
9267                | 882 | Brooklyn Nets                
9269                | 883 | Charlotte Hornets            
9270                | 884 | Chicago Bulls                
9271                | 885 | Cleveland Cavaliers          
9272                | 886 | Dallas Mavericks             
9273                | 887 | Denver Nuggets               
9274                | 888 | Detroit Pistons              
9275                | 889 | Golden State Warriors        
9276                | 890 | Houston Rockets              
9277                | 891 | Indiana Pacers               
9278                | 892 | Los Angeles Clippers         
9279                | 893 | Los Angeles Lakers           
9280                | 894 | Memphis Grizzlies            
9281                | 895 | Miami Heat                   
9282                | 896 | Milwaukee Bucks              
9283                | 897 | Minnesota Timberwolves       
9284                | 898 | New Orleans Pelicans         
9285                | 899 | New York Knicks              
9286                | 900 | Oklahoma City Thunder        
9287                | 901 | Orlando Magic                
9288                | 902 | Philadelphia 76ers           
9289                | 903 | Phoenix Suns                 
9290                | 904 | Portland Trail Blazers       
9292                | 905 | Sacramento Kings             
9291                | 906 | San Antonio Spurs            
9293                | 907 | Toronto Raptors              
9294                | 908 | Utah Jazz                    
9295                | 909 | Washington Wizards           
9296                | 920 | Anaheim Ducks                
9297                | 921 | Boston Bruins                
9298                | 922 | Buffalo Sabres               
9301                | 923 | Calgary Flames               
9299                | 924 | Carolina Hurricanes          
9302                | 925 | Chicago Blackhawks           
9303                | 926 | Colorado Avalanche           
9300                | 927 | Columbus Blue Jackets        
9304                | 928 | Dallas Stars                 
9305                | 929 | Detroit Red Wings            
9306                | 930 | Edmonton Oilers              
9307                | 931 | Florida Panthers             
9308                | 932 | Los Angeles Kings            
9309                | 933 | Minnesota Wild               
9310                | 934 | Montreal Canadiens           
9312                | 935 | Nashville Predators          
9311                | 936 | New Jersey Devils            
9313                | 937 | New York Islanders           
9314                | 938 | New York Rangers             
9315                | 939 | Ottawa Senators              
9316                | 940 | Philadelphia Flyers          
9318                | 941 | Pittsburgh Penguins          
9319                | 942 | San Jose Sharks              
9550                | 943 | Seattle Kraken               
9320                | 944 | St. Louis Blues              
9321                | 945 | Tampa Bay Lightning          
9322                | 946 | Toronto Maple Leafs          
9635                | 947 | Utah Hockey Club             
9323                | 948 | Vancouver Canucks            
9453                | 949 | Vegas Golden Knights         
9324                | 950 | Washington Capitals          
9325                | 951 | Winnipeg Jets                
9220                | 952 | Big 12 952                   
9422                | 953 | Big 12 953                   
9423                | 954 | Big 12 954                   
9424                | 955 | ACC 955                      
9425                | 956 | ACC 956                      
9426                | 957 | Big Ten 957                  
9427                | 958 | Big Ten 958                  
9428                | 959 | Big Ten 959                  
9223                | 960 | SEC 960                      
9221                | 961 | SEC 961                      
9222                | 962 | SEC 962                      
9631                | 963 | Sports 963                   
9224                | 964 | Sports 964                   
9225                | 965 | Sports 965                   
9226                | 966 | Sports 966                   
9227                | 967 | Sports 967                   
9228                | 968 | Sports 968                   
9229                | 969 | Sports 969                   
9207                | 970 | Sports 970                   
9208                | 971 | Sports 971                   
9209                | 972 | Sports 972                   
9210                | 973 | Sports 973                   
9211                | 974 | Sports 974                   
9212                | 975 | Sports 975                   
9213                | 976 | Sports 976                   
9214                | 977 | Sports 977                   
9215                | 978 | Sports 978                   
9216                | 979 | Sports 979                   
9261                | 980 | Sports 980                   
9262                | 981 | Sports 981                   
9326                | 982 | Sports 982                   
9327                | 983 | Sports 983                   
9328                | 984 | Sports 984                   
9329                | 985 | Sports 985                   
9330                | 986 | Sports 986                   
9331                | 987 | Sports 987                   
9332                | 988 | Sports 988                   
9333                | 989 | Sports 989                   
9334                | 990 | Sports 990                   
9335                | 991 | Sports 991                   
9336                | 992 | Sports 992                   
9337                | 993 | Sports 993                   
9338                | 994 | Sports 994                   
9602                | 995 | Sports 995                   
9603                | 996 | Sports 996                   
9604                | 997 | Sports 997                   
9605                | 998 | Sports 998                   
9606                | 999 | Sports 999
```

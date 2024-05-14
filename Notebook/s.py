import numpy as np  
import matplotlib.pyplot as plt  
  
X = ['CVE-ID','CVE-ID','CVE-ID','CVE-ID'] 
Ygirls = [10,20,20,40] 
Zboys = [20,30,25,30] 
Aboys = [10,20,15,35] 

  
X_axis = np.arange(len(X)) 
  
plt.bar(X_axis - 0.3, Ygirls, 0.3, label = 'Base Score', color = '#ffbb3d') 
plt.bar(X_axis, Zboys, 0.3, label = 'Explotability Score', color = '#ff8888') 
plt.bar(X_axis + 0.3, Aboys, 0.3, label = 'Impact Score', color = '#ff4444') 

  
plt.xticks(X_axis, X) 
plt.xlabel("CVE IDENTIFIER") 
plt.ylabel("SCORE") 
plt.title("Scores of the top ten vulnerabilities") 
plt.legend() 
plt.show() 
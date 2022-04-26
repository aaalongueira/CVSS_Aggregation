#!/usr/bin/env python
# coding: utf-8

# In[1]:


import random
import csv
import statistics


# In[2]:


# Function that implements the addition of two values using the Bayesian sum
def bayesianAddition(a, b):
    """This function implements the addition of 2 numbers using the Bayesian sum described in MAGERIT"""
    return( ( 1 - ( 1 - a/10 )*( 1 - b/10 ) )*10 )

def bayesianAddList(cvssList):
    result = 0
    for i in cvssList:
        result = bayesianAddition( result, i )
    return result


# In[3]:


# Import CVSS data of the first distribution
file = open('Distribution_5.csv', encoding='utf-8-sig')
data_1 = csv.reader(file)
rows = []
for row in data_1:
        rows.append(row)
cvss = []
for value in rows:
    cvss.append(float(value[0]))
file.close()


# In[4]:


# Number of CVSSs in the dataset
n_cvss = len(cvss)


# In[5]:


# Generation of the number of layers:
n_layers = random.randint( 2, 20 )


# In[6]:


# Assigment of a random layer to each CVSS
deepness = []
for value in cvss:
    deepness.append( random.randint( 2, n_layers ) )


# In[7]:


# Interpolation to obtain the deepness factor according to the deepness in the graph:
# y = mx + n
n = ( ( 1 - n_layers*n_layers ) / ( n_layers*( 1 - n_layers ) ) )
m = 1 - n
deepness_Factor = []
for value in deepness:
    deepness_Factor.append( m*value + n )


# In[8]:


# Generation of a random funcionality value for each CVSS
functionality_Factor = []
for value in cvss:
    functionality_Factor.append( random.randint( 0, 1 ) )


# In[9]:


# Generation of a random context value for each CVSS
context_Factor = []
for value in cvss:
    context_Factor.append( random.randint( 0, 1 ) )


# In[10]:


# Generation of a random exploit value for each CVSS
exploit_Factor = []
for value in cvss:
    exploit_Factor.append( random.choice( [0, 1.25, 1.5, 1.75, 2] ) )


# In[11]:


# Calculation of the average factor. In this use case, we use the arithmetic mean of the data:
sum = 0
for value in cvss:
    sum = sum + value
average_Factor = sum / len( cvss )


# In[12]:


# Calculation of lambda (Summarized Factor)
# lambda = deepness_Factor * functionality_Factor * context_Factor * exploit_Factor
lambda_factor = []
for (deepFact, functFact, contFact, expFact) in zip(deepness_Factor, functionality_Factor, context_Factor, exploit_Factor):
    lambda_factor.append( deepFact*functFact*contFact*expFact )


# In[13]:


# Final CVSS value to be aggregated
cvss_modified = []
for (lambdaFact, cvssAUX) in zip( lambda_factor, cvss ):
    cvss_modified.append( lambdaFact*cvssAUX )


# In[14]:


# Check for overflows because of the exploit factor:
cvss_final = []
for value in cvss_modified:
    if ( value ) > 10:
        cvss_final.append( 10.0 )
    else:
        cvss_final.append( round(value, 2) )


# In[21]:


# Finally, values of CVSS are aggregated
# def addition(lista):
#     if lista:
#         return 0
#     return lista[0]+addition(lista[1:])

# def addtion_it(lista)
#     suma = 0
#     for i in lista:
#         suma += i
#     return suma
aggregation = round( (10 - bayesianAddList(cvss_final) / average_Factor), 2 )


# In[22]:


aggregation


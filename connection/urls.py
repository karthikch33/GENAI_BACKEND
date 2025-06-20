from django.contrib import admin
from django.urls import path
from . import views
urlpatterns = [
    path('',views.home,name="home"),
    path('api/sapconn/',views.SAPconn,name="SAPconn"),
    path('api/hanaconn/',views.HANAconn,name="HANAconn"),
    path('api/hanatables/<int:p_id>/<str:c_name>/',views.HANAtables,name="hanatables"),
    path('api/hanadata/',views.HANAtables,name="HANAtables"),
 
 
    path('api/saptables/<int:load>/<int:connection_id>/',views.SAPtables,name="SAPtables"),
    path('api/SAPTableSearch/<str:tab>/<int:connection_id>/',views.SAPTableSearch,name="SAPTableSearch"),
 

    # project CURD
    path('api/Pcreate/',views.ProjectCreate,name="Pcreate"),
    path('api/Pget/',views.ProjectGet,name="Pget"),
    path('api/PgetSingle/<int:p_id>/',views.ProjectGetSingle,name="PgetSingle"),
    path('api/PUpdate/<int:pk>/',views.projectUpdate,name="PUpdate"),
    path('api/PDelete/<int:pk>/',views.project_delete,name="PDelete"),

    
    
    # connection CURD
    path('api/Ccreate/',views.ConnectionCreate,name="Ccreate"),
    path('api/Cupdate/<int:p_id>/<str:c_name>/', views.ConnectionUpdate, name='Cupdate'),
    path('api/Cget/',views.ConnectionGet,name="Cget"),
    path('api/Cdelete/<int:p_id>/<str:c_name>/',views.connectionDelete,name="Cdelete"),
    path('api/CgetSingle/<int:p_id>/<str:c_name>/',views.ConnectionGetSingle,name="CgetSingle"),
    path('api/Crename/<str:re_val>/<int:p_id>/<str:c_name>/',views.connectionRename,name="Crename"),

    path('xls/',views.xls_read,name="xls_read"),
    path('api/ObjGet/<int:oid>/',views.objects_get,name="objects_get"),
    path('api/ObjCreate/',views.objects_create,name="objects_create"),
    path('api/ObjUpdate/<int:oid>/',views.objects_update,name="objects_update"),
    path('api/ObjDelete/<int:oid>/',views.objects_delete,name="objects_delete"),
 
 
    #Rules Page API's
    path('api/PdataObject/<int:pid>/<str:ptype>/',views.project_dataObject,name="project_dataObject"),
    path('api/Osegements/<int:pid>/<int:oid>/',views.DataObject_Segements,name="DataObject_Segements"),
    path('api/Sfields/<int:pid>/<int:oid>/<int:sid>/',views.Segements_Fields,name="Segements_Fields"),
    path('api/getTable/<int:sid>/',views.getTableData,name="getTableData"),
    path('api/execute_queries/<int:pid>/<int:oid>/<int:sid>/',views.execute_queries,name="execute_queries"),

    path('api/getLatestVersion/<int:pid>/<int:oid>/<int:sid>/',views.getLatestVersion,name="getLatestVersion"),
    path('api/applyOneToOne/<int:pid>/<int:oid>/<int:sid>/',views.applyOneToOne,name="applyOneToOne"),
    # path('api/getSapTableData',views.getSapTableData,name="getSapTableData"),
 

 #CHAT
 path('api/createChat/',views.CreateChat,name="createChat"),
    path('api/getChat/<int:pid>/<int:oid>/<int:sid>/',views.getChat,name="getChat"),
 
    path('xls/',views.xls_read,name="xls_read"),
    path('tableDelete/',views.tableDelete,name="tableDelete"),
    

      # file CURD
    path('api/fcreate/',views.fileCreate,name="fcreate"),
    path('api/fupdate/<int:p_id>/<str:f_name>/', views.fileUpdate, name='fupdate'),
    path('api/fget/',views.fileGet,name="fget"),
    path('api/fdelete/<int:p_id>/<str:f_name>/',views.fileDelete,name="fdelete"),
    path('api/fgetSingle/<int:p_id>/<str:f_name>/',views.fileGetSingle,name="fgetSingle"),
    path('api/frename/<str:re_val>/<int:p_id>/<str:f_name>/',views.fileRename,name="frename"),
 
    #file
    path('excel/', views.GetXL.as_view(), name = "by"),
    path('txt/', views.GetTXT.as_view(), name = "hi"),
    path('csv/', views.GetFile.as_view(), name = "by"),
    path('xlsx/', views.GetXLSheet.as_view(), name = "hlo"),




      #VersionsRule API's
    path('api/VersionRuleCreate/',views.VersionRuleCreate,name="VersionRuleCreate"),
 
 
 
    #Save Rule Api's
    path('api/CreateSaveRules/',views.SaveRuleCreate,name="CreateSaveRules"),
    path('api/GetSaveRules/<int:pid>/<int:oid>/<int:sid>/',views.GetSaveRule,name="GetSaveRule"),
 
    # path('api/RuleVersions/<int:pid>/<int:oid>/<int:sid>/',views.RuleVersions,name="RuleVersions"),
    path('api/VersionData/<int:pid>/<int:oid>/<int:sid>/<int:vid>/',views.VerisonData,name="VerisonData"),


     path('api/getSapTableData',views.getSapTableData,name="getSapTableData"),

    #success Factors 
    path('saveSuccessFactors/', views.saveSuccessFactors, name = "saveSuccessFactors"),
    path('api/getSfTableData/<int:oid>/', views.getSfTableData, name = "getSfTableData"),
    path('reUploadSuccessFactors/<int:oid>/', views.reUploadSuccessFactors, name = "reUploadSuccessFactors"),

    path('plot/<str:pid>/<str:oid>/<str:sid>/', views.GetPlot.as_view(), name = "plot"),
    path('particular/<str:pid>/<str:oid>/<str:sid>/<str:fname>/', views.GetExactGraph.as_view(), name = "Exact"),



 
    #validations
    path('api/create_Validation_Table/', views.create_Validation_Table, name = "create_Validation_Table"),
    path('api/Insert_Data_Into_ValidationTable/', views.Insert_Data_Into_ValidationTable, name = "Insert_Data_Into_ValidationTable"),
    path('api/create_PreLoad_Tables/', views.create_PreLoad_Tables, name = "create_PreLoad_Tables"),
    path('api/validate_mandatory_fields/', views.validate_mandatory_fields, name = "validate_mandatory_fields"),
    path('api/validate_Lookup_fields/', views.validate_Lookup_fields, name = "validate_Lookup_fields"),
    path('api/get_validation_table/<int:seg_id>/', views.get_validation_table, name = "get_validation_table"),
 
 
    #Final Report
    path('api/final_report/<int:project_id>/', views.final_report, name = "final_report"),
    path('api/get_report_table/<int:segment_id>/<str:table_type>/', views.get_report_table, name = "get_report_table"),
    path('api/download_final_report/<int:segment_id>/<str:table_type>/', views.download_final_report, name = "download_final_report"),
    path('api/get_numberOfLookupValidationFailed_Count/', views.get_numberOfLookupValidationFailed_Count, name = "get_numberOfLookupValidationFailed_Count"),
 
 
 
]

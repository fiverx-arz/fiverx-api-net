﻿//------------------------------------------------------------------------------
// <auto-generated>
//     Dieser Code wurde von einem Tool generiert.
//     Laufzeitversion:4.0.30319.18063
//
//     Änderungen an dieser Datei können falsches Verhalten verursachen und gehen verloren, wenn
//     der Code erneut generiert wird.
// </auto-generated>
//------------------------------------------------------------------------------

namespace FiverxLinkSecurityTestClient.FiveRxSecurityService {
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://fiverx.de/security/SV0100", ConfigurationName="FiveRxSecurityService.FiveRxLinkSecurityServiceSoap")]
    public interface FiveRxLinkSecurityServiceSoap {
        
        // CODEGEN: Der Nachrichtenvertrag wird generiert, da der Vorgang ladeRzSecurityVersion weder in RPC noch in einem Dokument eingeschlossen ist.
        [System.ServiceModel.OperationContractAttribute(Action="ladeRzSecurityVersionRequest", ReplyAction="*")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionResponse1 ladeRzSecurityVersion(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionRequest1 request);
        
        // CODEGEN: Der Nachrichtenvertrag wird generiert, da der Vorgang ladeRzZertifikat weder in RPC noch in einem Dokument eingeschlossen ist.
        [System.ServiceModel.OperationContractAttribute(Action="ladeRzZertifikatRequest", ReplyAction="*")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatResponse1 ladeRzZertifikat(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatRequest1 request);
        
        // CODEGEN: Der Nachrichtenvertrag wird generiert, da der Vorgang ladeRzSicherheitsmerkmale weder in RPC noch in einem Dokument eingeschlossen ist.
        [System.ServiceModel.OperationContractAttribute(Action="ladeRzSicherheitsmerkmaleRequest", ReplyAction="*")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleResponse1 ladeRzSicherheitsmerkmale(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest1 request);
        
        // CODEGEN: Der Nachrichtenvertrag wird generiert, da der Vorgang verarbeiteAuftrag weder in RPC noch in einem Dokument eingeschlossen ist.
        [System.ServiceModel.OperationContractAttribute(Action="verarbeiteAuftragRequest", ReplyAction="*")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragResponse1 verarbeiteAuftrag(FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragRequest1 request);
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/SV0100")]
    public partial class ladeRzSecurityVersionRequest : object, System.ComponentModel.INotifyPropertyChanged {
        
        private einParameterRequestMsg ladeRzSecurityVersionRequestMsgField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public einParameterRequestMsg ladeRzSecurityVersionRequestMsg {
            get {
                return this.ladeRzSecurityVersionRequestMsgField;
            }
            set {
                this.ladeRzSecurityVersionRequestMsgField = value;
                this.RaisePropertyChanged("ladeRzSecurityVersionRequestMsg");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/types")]
    public partial class einParameterRequestMsg : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string rzeEingabeDatenField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified, Order=0)]
        public string rzeEingabeDaten {
            get {
                return this.rzeEingabeDatenField;
            }
            set {
                this.rzeEingabeDatenField = value;
                this.RaisePropertyChanged("rzeEingabeDaten");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/SV0100/types")]
    public partial class verarbeiteAuftragResponse : object, System.ComponentModel.INotifyPropertyChanged {
        
        private genericResponseMsg verarbeiteAuftragResponseMsgField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public genericResponseMsg verarbeiteAuftragResponseMsg {
            get {
                return this.verarbeiteAuftragResponseMsgField;
            }
            set {
                this.verarbeiteAuftragResponseMsgField = value;
                this.RaisePropertyChanged("verarbeiteAuftragResponseMsg");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/types")]
    public partial class genericResponseMsg : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string rzeAusgabeDatenField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified, Order=0)]
        public string rzeAusgabeDaten {
            get {
                return this.rzeAusgabeDatenField;
            }
            set {
                this.rzeAusgabeDatenField = value;
                this.RaisePropertyChanged("rzeAusgabeDaten");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/SV0100")]
    public partial class verarbeiteAuftragRequest : object, System.ComponentModel.INotifyPropertyChanged {
        
        private zweiParameterRequestMsg verarbeiteAuftragRequestMsgField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public zweiParameterRequestMsg verarbeiteAuftragRequestMsg {
            get {
                return this.verarbeiteAuftragRequestMsgField;
            }
            set {
                this.verarbeiteAuftragRequestMsgField = value;
                this.RaisePropertyChanged("verarbeiteAuftragRequestMsg");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/types")]
    public partial class zweiParameterRequestMsg : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string rzeEingabeDatenField;
        
        private string rzeLadeRzSecurityVersionField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified, Order=0)]
        public string rzeEingabeDaten {
            get {
                return this.rzeEingabeDatenField;
            }
            set {
                this.rzeEingabeDatenField = value;
                this.RaisePropertyChanged("rzeEingabeDaten");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified, Order=1)]
        public string rzeLadeRzSecurityVersion {
            get {
                return this.rzeLadeRzSecurityVersionField;
            }
            set {
                this.rzeLadeRzSecurityVersionField = value;
                this.RaisePropertyChanged("rzeLadeRzSecurityVersion");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/SV0100/types")]
    public partial class ladeRzSicherheitsmerkmaleResponse : object, System.ComponentModel.INotifyPropertyChanged {
        
        private genericResponseMsg ladeRzSicherheitsmerkmaleResponseMsgField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public genericResponseMsg ladeRzSicherheitsmerkmaleResponseMsg {
            get {
                return this.ladeRzSicherheitsmerkmaleResponseMsgField;
            }
            set {
                this.ladeRzSicherheitsmerkmaleResponseMsgField = value;
                this.RaisePropertyChanged("ladeRzSicherheitsmerkmaleResponseMsg");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/SV0100")]
    public partial class ladeRzSicherheitsmerkmaleRequest : object, System.ComponentModel.INotifyPropertyChanged {
        
        private zweiParameterRequestMsg ladeRzSicherheitsmerkmaleRequestMsgField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public zweiParameterRequestMsg ladeRzSicherheitsmerkmaleRequestMsg {
            get {
                return this.ladeRzSicherheitsmerkmaleRequestMsgField;
            }
            set {
                this.ladeRzSicherheitsmerkmaleRequestMsgField = value;
                this.RaisePropertyChanged("ladeRzSicherheitsmerkmaleRequestMsg");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/SV0100/types")]
    public partial class ladeRzZertifikatResponse : object, System.ComponentModel.INotifyPropertyChanged {
        
        private genericResponseMsg ladeRzZertifikatResponseMsgField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public genericResponseMsg ladeRzZertifikatResponseMsg {
            get {
                return this.ladeRzZertifikatResponseMsgField;
            }
            set {
                this.ladeRzZertifikatResponseMsgField = value;
                this.RaisePropertyChanged("ladeRzZertifikatResponseMsg");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/SV0100")]
    public partial class ladeRzZertifikatRequest : object, System.ComponentModel.INotifyPropertyChanged {
        
        private zweiParameterRequestMsg ladeRzZertifikatRequestMsgField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public zweiParameterRequestMsg ladeRzZertifikatRequestMsg {
            get {
                return this.ladeRzZertifikatRequestMsgField;
            }
            set {
                this.ladeRzZertifikatRequestMsgField = value;
                this.RaisePropertyChanged("ladeRzZertifikatRequestMsg");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.0.30319.34234")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://fiverx.de/security/SV0100/types")]
    public partial class ladeRzSecurityVersionResponse : object, System.ComponentModel.INotifyPropertyChanged {
        
        private genericResponseMsg ladeRzSecurityVersionResponseMsgField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public genericResponseMsg ladeRzSecurityVersionResponseMsg {
            get {
                return this.ladeRzSecurityVersionResponseMsgField;
            }
            set {
                this.ladeRzSecurityVersionResponseMsgField = value;
                this.RaisePropertyChanged("ladeRzSecurityVersionResponseMsg");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class ladeRzSecurityVersionRequest1 {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://fiverx.de/security/SV0100", Order=0)]
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionRequest requestSecurityVersion;
        
        public ladeRzSecurityVersionRequest1() {
        }
        
        public ladeRzSecurityVersionRequest1(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionRequest requestSecurityVersion) {
            this.requestSecurityVersion = requestSecurityVersion;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class ladeRzSecurityVersionResponse1 {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://fiverx.de/security/SV0100/types", Order=0)]
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionResponse ladeRzSecurityVersionResponse;
        
        public ladeRzSecurityVersionResponse1() {
        }
        
        public ladeRzSecurityVersionResponse1(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionResponse ladeRzSecurityVersionResponse) {
            this.ladeRzSecurityVersionResponse = ladeRzSecurityVersionResponse;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class ladeRzZertifikatRequest1 {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://fiverx.de/security/SV0100", Order=0)]
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatRequest requestladeRzZertifikat;
        
        public ladeRzZertifikatRequest1() {
        }
        
        public ladeRzZertifikatRequest1(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatRequest requestladeRzZertifikat) {
            this.requestladeRzZertifikat = requestladeRzZertifikat;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class ladeRzZertifikatResponse1 {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://fiverx.de/security/SV0100/types", Order=0)]
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatResponse ladeRzZertifikatResponse;
        
        public ladeRzZertifikatResponse1() {
        }
        
        public ladeRzZertifikatResponse1(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatResponse ladeRzZertifikatResponse) {
            this.ladeRzZertifikatResponse = ladeRzZertifikatResponse;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class ladeRzSicherheitsmerkmaleRequest1 {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://fiverx.de/security/SV0100", Order=0)]
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest requestladeRzSicherheitsmerkmal;
        
        public ladeRzSicherheitsmerkmaleRequest1() {
        }
        
        public ladeRzSicherheitsmerkmaleRequest1(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest requestladeRzSicherheitsmerkmal) {
            this.requestladeRzSicherheitsmerkmal = requestladeRzSicherheitsmerkmal;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class ladeRzSicherheitsmerkmaleResponse1 {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://fiverx.de/security/SV0100/types", Order=0)]
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleResponse ladeRzSicherheitsmerkmaleResponse;
        
        public ladeRzSicherheitsmerkmaleResponse1() {
        }
        
        public ladeRzSicherheitsmerkmaleResponse1(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleResponse ladeRzSicherheitsmerkmaleResponse) {
            this.ladeRzSicherheitsmerkmaleResponse = ladeRzSicherheitsmerkmaleResponse;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class verarbeiteAuftragRequest1 {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://fiverx.de/security/SV0100", Order=0)]
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragRequest requestAuftrag;
        
        public verarbeiteAuftragRequest1() {
        }
        
        public verarbeiteAuftragRequest1(FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragRequest requestAuftrag) {
            this.requestAuftrag = requestAuftrag;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class verarbeiteAuftragResponse1 {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://fiverx.de/security/SV0100/types", Order=0)]
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragResponse verarbeiteAuftragResponse;
        
        public verarbeiteAuftragResponse1() {
        }
        
        public verarbeiteAuftragResponse1(FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragResponse verarbeiteAuftragResponse) {
            this.verarbeiteAuftragResponse = verarbeiteAuftragResponse;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface FiveRxLinkSecurityServiceSoapChannel : FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap, System.ServiceModel.IClientChannel {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class FiveRxLinkSecurityServiceSoapClient : System.ServiceModel.ClientBase<FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap>, FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap {
        
        public FiveRxLinkSecurityServiceSoapClient() {
        }
        
        public FiveRxLinkSecurityServiceSoapClient(string endpointConfigurationName) : 
                base(endpointConfigurationName) {
        }
        
        public FiveRxLinkSecurityServiceSoapClient(string endpointConfigurationName, string remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public FiveRxLinkSecurityServiceSoapClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public FiveRxLinkSecurityServiceSoapClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress) {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionResponse1 FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap.ladeRzSecurityVersion(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionRequest1 request) {
            return base.Channel.ladeRzSecurityVersion(request);
        }
        
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionResponse ladeRzSecurityVersion(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionRequest requestSecurityVersion) {
            FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionRequest1 inValue = new FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionRequest1();
            inValue.requestSecurityVersion = requestSecurityVersion;
            FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSecurityVersionResponse1 retVal = ((FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap)(this)).ladeRzSecurityVersion(inValue);
            return retVal.ladeRzSecurityVersionResponse;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatResponse1 FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap.ladeRzZertifikat(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatRequest1 request) {
            return base.Channel.ladeRzZertifikat(request);
        }
        
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatResponse ladeRzZertifikat(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatRequest requestladeRzZertifikat) {
            FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatRequest1 inValue = new FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatRequest1();
            inValue.requestladeRzZertifikat = requestladeRzZertifikat;
            FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzZertifikatResponse1 retVal = ((FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap)(this)).ladeRzZertifikat(inValue);
            return retVal.ladeRzZertifikatResponse;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleResponse1 FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap.ladeRzSicherheitsmerkmale(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest1 request) {
            return base.Channel.ladeRzSicherheitsmerkmale(request);
        }
        
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleResponse ladeRzSicherheitsmerkmale(FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest requestladeRzSicherheitsmerkmal) {
            FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest1 inValue = new FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleRequest1();
            inValue.requestladeRzSicherheitsmerkmal = requestladeRzSicherheitsmerkmal;
            FiverxLinkSecurityTestClient.FiveRxSecurityService.ladeRzSicherheitsmerkmaleResponse1 retVal = ((FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap)(this)).ladeRzSicherheitsmerkmale(inValue);
            return retVal.ladeRzSicherheitsmerkmaleResponse;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragResponse1 FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap.verarbeiteAuftrag(FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragRequest1 request) {
            return base.Channel.verarbeiteAuftrag(request);
        }
        
        public FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragResponse verarbeiteAuftrag(FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragRequest requestAuftrag) {
            FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragRequest1 inValue = new FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragRequest1();
            inValue.requestAuftrag = requestAuftrag;
            FiverxLinkSecurityTestClient.FiveRxSecurityService.verarbeiteAuftragResponse1 retVal = ((FiverxLinkSecurityTestClient.FiveRxSecurityService.FiveRxLinkSecurityServiceSoap)(this)).verarbeiteAuftrag(inValue);
            return retVal.verarbeiteAuftragResponse;
        }
    }
}
